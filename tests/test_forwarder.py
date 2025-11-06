"""Test cases for plugin output."""

import json
from unittest import mock

import assemblyline_client as al
from azul_runner import (
    JobResult,
    State,
    test_template,
)

from azul_plugin_assemblyline import common, forwarder
from azul_plugin_assemblyline.forwarder import AzulPluginAssemblylineForwarder
from tests.support import resetEnv


class TestExecute(test_template.TestPlugin):
    PLUGIN_TO_TEST = AzulPluginAssemblylineForwarder

    def setUp(self):
        resetEnv()
        # Mock Assemblyline client to prevent the init of the plugin from failing.
        self.original_setup_client = common.setup_al_client
        mock_setup_al_client = mock.MagicMock()
        self.mock_al_client = mock.MagicMock()
        mock_setup_al_client.return_value = self.mock_al_client
        common.setup_al_client = mock_setup_al_client
        # Ensure we don't have to wait for re-attempt sleeps
        forwarder.CLIENT_RETRY_SLEEP_SECONDS = 0
        return super().setUp()

    def tearDown(self):
        common.setup_al_client = self.original_setup_client

    def test_execute_hash_already_seen(self):
        """Test an expected normal run"""
        content = self.load_test_file_bytes(
            "cc63001c78b8e92131da07d0dfe03a780c02065bcc9598b6841da6fb67b96b51",
            "Malicious trojan windows 32 Executable.",
        )

        sample_found = json.loads(
            self.load_local_raw(
                "hash_search",
                "sample_found.json",
                description="Example of json response when a sample is already in assemblyline.",
            ).decode()
        )
        self.mock_al_client.hash_search.return_value = sample_found

        result = self.do_execution(data_in=[("content", content)], no_multiprocessing=True)
        self.assertJobResult(
            result,
            JobResult(
                state=State(
                    State.Label.OPT_OUT,
                    failure_name="Already in Assemblyline",
                    message="Checked Assemblyline and already there.",
                )
            ),
        )
        self.mock_al_client.hash_search.assert_called()

    def test_execute_bad_al_response_from_hash_search(self):
        """Test an expected normal run"""
        content = self.load_test_file_bytes(
            "cc63001c78b8e92131da07d0dfe03a780c02065bcc9598b6841da6fb67b96b51",
            "Malicious trojan windows 32 Executable.",
        )

        self.mock_al_client.hash_search.return_value = {}

        result = self.do_execution(data_in=[("content", content)], no_multiprocessing=True)
        result.state.message = None
        self.assertJobResult(result, JobResult(state=State(State.Label.ERROR_EXCEPTION)))
        self.mock_al_client.hash_search.assert_called()

    def test_execute_al_continual_error(self):
        """Test an expected normal run"""
        content = self.load_test_file_bytes(
            "cc63001c78b8e92131da07d0dfe03a780c02065bcc9598b6841da6fb67b96b51",
            "Malicious trojan windows 32 Executable.",
        )

        def anyRaiseClientError(*args, **kwargs):
            raise al.ClientError(message="test", status_code=500)

        self.mock_al_client.hash_search.side_effect = anyRaiseClientError

        result = self.do_execution(data_in=[("content", content)], no_multiprocessing=True)
        self.assertJobResult(
            result,
            JobResult(
                state=State(
                    State.Label.ERROR_EXCEPTION,
                    failure_name="Assemblyline Network Error",
                    message="Couldn't contact Assemblyline with status code: 500 message: None",
                )
            ),
        )
        self.mock_al_client.hash_search.assert_called()

    def test_execute_normal(self):
        """Test an expected normal run"""
        content = self.load_test_file_bytes(
            "cc63001c78b8e92131da07d0dfe03a780c02065bcc9598b6841da6fb67b96b51",
            "Malicious trojan windows 32 Executable.",
        )
        result = self.do_execution(data_in=[("content", content)], no_multiprocessing=True)
        self.assertJobResult(
            result,
            JobResult(state=State(State.Label.COMPLETED_EMPTY)),
        )
        self.mock_al_client.hash_search.assert_called_once()
        self.mock_al_client.ingest.assert_called_once()

    def test_execute_some_errors(self):
        """Test a run that finds it's hash after multiple retries and then continues as a normal run"""
        content = self.load_test_file_bytes(
            "cc63001c78b8e92131da07d0dfe03a780c02065bcc9598b6841da6fb67b96b51",
            "Malicious trojan windows 32 Executable.",
        )

        counter = 0
        RETRIES_UNTIL_SUCCESS = 5
        sample_not_found = json.loads(
            self.load_local_raw(
                "hash_search",
                "sample_not_found.json",
                description="Example of a json response where the same isn't found in Assemblyline.",
            ).decode()
        )

        def succeed_after_5_attempts(*args, **kwargs):
            nonlocal counter
            counter += 1
            if counter % RETRIES_UNTIL_SUCCESS == 0:
                return sample_not_found
            raise al.ClientError(message="test", status_code=500)

        self.mock_al_client.hash_search.side_effect = succeed_after_5_attempts
        self.mock_al_client.ingest.side_effect = succeed_after_5_attempts

        result = self.do_execution(data_in=[("content", content)], no_multiprocessing=True)
        self.assertJobResult(
            result,
            JobResult(state=State(State.Label.COMPLETED_EMPTY)),
        )
        self.assertEqual(self.mock_al_client.hash_search.call_count, RETRIES_UNTIL_SUCCESS)
        self.assertEqual(self.mock_al_client.ingest.call_count, RETRIES_UNTIL_SUCCESS)
