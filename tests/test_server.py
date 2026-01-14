import copy
import datetime
import importlib
import io
import json
import unittest
from multiprocessing import shared_memory
from unittest import mock

import cart
import httpx
from azul_bedrock import models_network as azm
from azul_runner import Plugin
from azul_runner.pusher import Pusher

# from starlette.testclient import TestClient
from fastapi.testclient import TestClient
from prometheus_client import REGISTRY

from azul_plugin_assemblyline import models
from azul_plugin_assemblyline.settings import Settings as alSettings
from tests.support import resetEnv


def get_app(mock_pusher: Pusher):
    from azul_plugin_assemblyline import main

    # De-register prometheus metrics between tests
    collectors = list(REGISTRY._collector_to_names.keys())
    for collector in collectors:
        REGISTRY.unregister(collector)

    # Reload or it causes bad behaviour between tests.
    importlib.reload(main)

    mock_create_pusher = mock.MagicMock()
    mock_create_pusher.return_value = mock_pusher

    main.create_pusher = mock_create_pusher
    client = TestClient(main.app)
    return client


def gen_submission_message_action():
    return {
        "is_cache": True,
        "score": 5,
        "submission": {
            "sid": "sid",
            "time": "",
            "files": [
                {
                    "name": "filename.txt",
                    "size": 32121,
                    "sha256": "example-sha256",
                }
            ],
            "metadata": {},
            "noticiation": {},
            "params": {
                "description": "Inspection of file: filename.txt",
                "type": "USER",
                "submitter": "auser",
            },
            "scan_key": "empty_scankey",
        },
    }


def gen_action(classification="TLP:CLEAR"):
    return {
        "is_cache": False,
        "score": 5,
        "submission": {
            "archive_ts": "",
            "classification": classification,
            "error_count": 4,
            "errors": [],
            "expiry_ts": "",
            "file_count": 0,
            "files": [
                {
                    "name": "filename.txt",
                    "size": 32121,
                    "sha256": "example-sha256",
                }
            ],
            "max_score": 0,
            "metadata": {},
            "params": {
                "description": "Inspection of file: filename.txt",
                "type": "USER",
                "submitter": "auser",
            },
            "results": ["a", "b", "c"],
            "sid": "sid",
            "state": "",
            "times": {
                "completed": "",
                "submitted": "",
            },
            "verdict": {},
            "scan_key": "empty_scankey",
        },
    }


def gen_tree(classification="TLP:CLEAR") -> dict:

    return {
        "c4a96518b134c88271036f542fb1f84965f75e8d0bdad613b64da705dde159e7": models.SubTree(
            **{
                "children": {
                    "98f940cb17165e4c855051c4e8e2bdd4a8d5e171a008febdad2ecdd8240750e2": {
                        "children": {
                            "72ca8fc6d0e6d84ac70464d34a701e60d28b2c93dc6f955b7635816e14199ce4": {
                                "children": {
                                    "a495a4b86c1eac64327d8cad2598044314d9176f0ac069fbea0cf0baf08b6c9b": {
                                        "children": {},
                                        "name": [
                                            "things/orbit.txt",
                                            "tester/things/orbit.txt",
                                        ],
                                        "score": 0,
                                        "sha256": "a495a4b86c1eac64327d8cad2598044314d9176f0ac069fbea0cf0baf08b6c9b",
                                        "size": 4,
                                        "truncated": False,
                                        "type": "text/plain",
                                    }
                                },
                                "name": ["tester/metronome.zip"],
                                "score": 0,
                                "sha256": "72ca8fc6d0e6d84ac70464d34a701e60d28b2c93dc6f955b7635816e14199ce4",
                                "size": 134,
                                "truncated": False,
                                "type": "archive/zip",
                            },
                            "e6dfab4aa1338811a8d679c4b9edb7291f3bbf493fa4f6b3da922ef82a4e3844": {
                                "children": {},
                                "name": ["tester/file1.txt"],
                                "score": 0,
                                "sha256": "e6dfab4aa1338811a8d679c4b9edb7291f3bbf493fa4f6b3da922ef82a4e3844",
                                "size": 21,
                                "truncated": False,
                                "type": "text/plain",
                            },
                        },
                        "name": ["tester/nested.zip"],
                        "score": 0,
                        "sha256": "98f940cb17165e4c855051c4e8e2bdd4a8d5e171a008febdad2ecdd8240750e2",
                        "size": 631,
                        "truncated": True,
                        "type": "archive/zip",
                    }
                },
                "name": ["tester.zip"],
                "score": 0,
                "sha256": "c4a96518b134c88271036f542fb1f84965f75e8d0bdad613b64da705dde159e7",
                "size": 1372,
                "truncated": True,
                "type": "archive/zip",
            }
        )
    }


def gen_full(classification="TLP:CLEAR") -> dict:
    return models.Full(
        classification=classification,
        error_count=0,
        errors={},
        file_count=1,
        files=[],
        file_infos={},
        file_tree=gen_tree(classification),
        results={
            "demostring1": models.Full.Result(
                response=models.Full.Result.Response(extracted=[], service_name="A", service_version="4.5.1.1"),
                classification=classification,
                result={},
                sha256="not-real-sha256-1",
            ),
            "demostring2": models.Full.Result(
                response=models.Full.Result.Response(
                    extracted=[],
                    service_name="A",
                    service_version="4.5.1.1",
                ),
                classification="TLP:INVALID",
                result={},
                sha256="not-real-sha256-2",
            ),
        },
        state="OK",
        params=models.Full.Params(
            classification=classification,
            deep_scan=True,
            description="nil",
            groups=[],
            submitter="not read",
            ttl=1,
            type="unknown",
        ),
    ).model_dump()


class TestBasic(unittest.IsolatedAsyncioTestCase):
    maxDiff = None

    def _setUp(self):
        resetEnv()
        self.al_settings = alSettings()
        self.mock_pusher = mock.MagicMock()
        self.client = get_app(self.mock_pusher)

    @mock.patch("assemblyline_client.get_client")
    async def test_basic(self, m_alc: mock.MagicMock):
        m_alc.return_value = alclient = mock.MagicMock()
        self._setUp()
        download_shared_list = shared_memory.ShareableList([0])

        alclient.file = mock.MagicMock()
        download = alclient.file.download = mock.MagicMock()
        # Mock carted file
        content_carted = io.BytesIO()
        cart.pack_stream(io.BytesIO(b"content"), content_carted)
        content_carted.seek(0)

        def download_side_effect(*args, **kwargs):
            """Set return value and collect args/kwargs."""
            download_shared_list[0] += 1
            return content_carted.getvalue()

        download.side_effect = download_side_effect

        alclient.ontology = mock.MagicMock()
        submission = alclient.ontology.submission = mock.MagicMock()
        submission.return_value = [{"ontology_structure": "yeah", "classification": "TLP:CLEAR"}]

        alclient.submission = mock.MagicMock()
        full = alclient.submission.full = mock.MagicMock()
        full.return_value = gen_full()

        action = gen_action()
        # Index 0 is call count, index 1 is serialized kwargs
        shared_list = shared_memory.ShareableList([0, "a" * 10000])

        def pusher_sideeffect(*args, **kwargs):
            """Set return value and collect args/kwargs."""
            shared_list[0] += 1
            kwargs_copy = copy.deepcopy(kwargs)
            for k, v in kwargs_copy.items():
                if isinstance(kwargs_copy[k], bytes):
                    kwargs_copy[k] = v.decode()
            # Drop the storage proxy files.
            kwargs_copy.pop("local")
            try:
                print(json.dumps(kwargs_copy))
            except Exception as e:
                print("Shared list exception occurred: ", e)
            shared_list[1] = json.dumps(kwargs_copy)

        self.mock_pusher.push_once_sourced.side_effect = pusher_sideeffect

        self.client = get_app(self.mock_pusher)

        response: httpx.Response = self.client.post("", json=action)
        print(response.content)
        self.assertEqual(200, response.status_code)

        # Note below asserts have commented above them the normal equivalent if shared memory
        # didn't have to be used to get data out of the subprocess

        # Should be 1 call for the root file being downloaded and then pushed
        self.assertEqual(download_shared_list[0], 1)
        self.assertEqual(shared_list[0], 1)

        # Verify first call argument is correct
        # args, kwargs = self.mock_pusher.push_once.call_args
        kwargs = shared_list[1]

        print("kwargs are", kwargs)
        print(json.loads(kwargs))
        self.assertEqual(
            json.loads(kwargs),
            {
                "content": "content",
                "source_label": "assemblyline",
                "references": {"type": "USER", "description": "Inspection", "user": "auser"},
                "security": "OFFICIAL TLP:CLEAR",
                "filename": "tester.zip",
            },
        )

    @mock.patch("assemblyline_client.get_client")
    async def test_forwarded_to_al_and_back(self, m_alc: mock.MagicMock):
        m_alc.return_value = alclient = mock.MagicMock()
        self._setUp()
        # Action that has metadata to indicate it's come from azul.
        action = gen_action()

        meta = models.AssemblylineAzulMetadata(
            sha256="dummy-sha256",
            azul_source=azm.Source(
                name="testing",
                path=[
                    azm.PathNode(
                        sha256="dummy-sha256",
                        action=azm.BinaryAction.Sourced,
                        timestamp=datetime.datetime.fromisoformat("2024-01-01T10:10:10.00000Z"),
                        author=azm.Author(
                            name="dummy-plugin",
                            security="OFFICIAL",
                        ),
                    )
                ],
                timestamp=datetime.datetime.fromisoformat("2024-01-01T10:10:10.00000Z"),
                security="OFFICIAL",
                references={"description": "azul descr", "custom_ref": "Custom reference value!"},
            ),
            azul_file_info=azm.FileInfo(
                sha256="dummy-sha256",
                sha512="dummy-sha512",
                size=1,
                file_format="text/plain",
            ),
        )
        meta_data = meta.model_dump()
        meta_data[self.al_settings.azul_instance_key] = self.al_settings.azul_instance
        action["submission"]["metadata"] = meta_data
        action["submission"]["params"]["description"] = "[azul] enrich file sourced from bingus"

        alclient.file = mock.MagicMock()

        alclient.ontology = mock.MagicMock()
        submission = alclient.ontology.submission = mock.MagicMock()
        submission.return_value = [{"ontology_structure": "yeah", "classification": "TLP:CLEAR"}]

        alclient.submission = mock.MagicMock()
        full = alclient.submission.full = mock.MagicMock()
        full.return_value = gen_full()

        # Index 0 is call count, index 1 is serialized kwargs
        shared_list = shared_memory.ShareableList([0, "a" * 10000])

        def pusher_sideeffect(*args, **kwargs):
            """Set return value and collect args/kwargs."""
            shared_list[0] += 1
            kwargs_copy = copy.deepcopy(kwargs)
            for k, v in kwargs_copy.items():
                if isinstance(kwargs_copy[k], bytes):
                    kwargs_copy[k] = v.decode()
                if isinstance(kwargs_copy[k], azm.Source):
                    kwargs_copy[k] = kwargs_copy[k].model_dump_json(exclude_defaults=True)
                if isinstance(kwargs_copy[k], azm.FileInfo):
                    kwargs_copy[k] = kwargs_copy[k].model_dump_json(exclude_defaults=True)
            # Drop the storage proxy files.
            kwargs_copy.pop("local")
            try:
                print(json.dumps(kwargs_copy))
            except Exception as e:
                print("Shared list exception occurred: ", e)
            shared_list[1] = json.dumps(kwargs_copy)

        generic_plugin = Plugin()
        generic_plugin.NAME = "myplugin"
        generic_plugin.VERSION = "1"
        generic_plugin.SECURITY = "OFFICIAL"
        self.mock_pusher.plugin = generic_plugin
        self.mock_pusher.push_once_mapped.side_effect = pusher_sideeffect

        self.client = get_app(self.mock_pusher)

        response: httpx.Response = self.client.post("", json=action)
        print(response.content)
        self.assertEqual(200, response.status_code)

        # Note below asserts have commented above them the normal equivalent if shared memory
        # didn't have to be used to get data out of the subprocess

        # Should be 1 call submitting an enriched event to azul.
        self.assertEqual(shared_list[0], 1)

        # Verify call args are roughly correct.
        print("expected\n", shared_list[1], "\nend expected")
        self.assertEqual(
            json.loads(shared_list[1]),
            {
                "source_file_info": '{"sha256":"dummy-sha256","sha512":"dummy-sha512","size":1,"file_format":"text/plain"}',
                "source_info": '{"security":"OFFICIAL","name":"testing","timestamp":"2024-01-01T10:10:10+00:00","references":{"description":"azul descr","custom_ref":"Custom reference value!"},"path":[{"sha256":"dummy-sha256","action":"sourced","timestamp":"2024-01-01T10:10:10+00:00","author":{"name":"dummy-plugin","security":"OFFICIAL"}}]}',
                "security": "OFFICIAL TLP:CLEAR",
                "relationship": {"external": "Enriched by Assemblyline"},
                "filename": "tester.zip",
            },
        )

        # send event from other instance of azul which should be filtered
        m_alc.return_value = alclient = mock.MagicMock()
        self._setUp()
        # Action that has metadata to indicate it's come from azul.
        action = gen_action()
        action["submission"]["metadata"] = {self.al_settings.azul_instance_key: "bingus"}

        alclient.file = mock.MagicMock()

        alclient.ontology = mock.MagicMock()
        submission = alclient.ontology.submission = mock.MagicMock()
        submission.return_value = [{"ontology_structure": "yeah", "classification": "TLP:CLEAR"}]

        alclient.submission = mock.MagicMock()
        full = alclient.submission.full = mock.MagicMock()
        full.return_value = gen_full()

        # Index 0 is call count, index 1 is serialized kwargs
        shared_list = shared_memory.ShareableList([0, "a" * 10000])

        generic_plugin = Plugin()
        generic_plugin.NAME = "myplugin"
        generic_plugin.VERSION = "1"
        generic_plugin.SECURITY = "OFFICIAL"
        self.mock_pusher.plugin = generic_plugin
        self.mock_pusher.push_once_mapped.side_effect = pusher_sideeffect

        self.client = get_app(self.mock_pusher)

        response: httpx.Response = self.client.post("", json=action)
        print(response.content)
        self.assertEqual(200, response.status_code)

        # Note below asserts have commented above them the normal equivalent if shared memory
        # didn't have to be used to get data out of the subprocess

        # Should be 0 call submitting an enriched event to azul.
        self.assertEqual(shared_list[0], 0)

    @mock.patch("assemblyline_client.get_client")
    async def test_bad_security(self, gc: mock.MagicMock):
        gc.return_value = alclient = mock.MagicMock()
        self._setUp()

        alclient.file = mock.MagicMock()
        download = alclient.file.download = mock.MagicMock()
        download.return_value = b"content"

        alclient.ontology = mock.MagicMock()
        submission = alclient.ontology.submission = mock.MagicMock()
        submission.return_value = [{"ontology_structure": "yeah", "classification": "TLP:RED"}]

        alclient.submission = mock.MagicMock()
        full = alclient.submission.full = mock.MagicMock()
        full.return_value = gen_full("TLP:RED")

        action = gen_action("TLP:RED")

        response: httpx.Response = self.client.post("", json=action)
        print(response.content)
        self.assertEqual(200, response.status_code)

        self.assertFalse(self.mock_pusher.called)

    async def test_description(self):
        resetEnv()
        from azul_plugin_assemblyline import main

        self.assertEqual("Inspection", main.fix_description("Inspection of file: blah.txt"))
        self.assertEqual(
            "Inspection",
            main.fix_description("[INGEST] Inspection of file: blah.txt"),
        )
        self.assertEqual("Resubmit", main.fix_description("Resubmit a thing for analysis"))
        self.assertEqual("Totally unique", main.fix_description("Totally unique"))

    @mock.patch("assemblyline_client.get_client")
    async def test_basic_cache_hit_submisson_message(self, m_alc: mock.MagicMock):
        m_alc.return_value = alclient = mock.MagicMock()
        self._setUp()
        download_shared_list = shared_memory.ShareableList([0])

        alclient.file = mock.MagicMock()
        download = alclient.file.download = mock.MagicMock()
        # Mock carted file
        content_carted = io.BytesIO()
        cart.pack_stream(io.BytesIO(b"content"), content_carted)
        content_carted.seek(0)

        def download_side_effect(*args, **kwargs):
            """Set return value and collect args/kwargs."""
            download_shared_list[0] += 1
            return content_carted.getvalue()

        download.side_effect = download_side_effect

        alclient.ontology = mock.MagicMock()
        ontology_submission = alclient.ontology.submission = mock.MagicMock()
        ontology_submission.return_value = [{"ontology_structure": "yeah", "classification": "TLP:CLEAR"}]

        submission_mock = alclient.submission = mock.MagicMock()
        full = alclient.submission.full = mock.MagicMock()
        full.return_value = gen_full()

        submission_mock.return_value = gen_action()["submission"]

        action = gen_submission_message_action()
        # Index 0 is call count, index 1 is serialized kwargs
        shared_list = shared_memory.ShareableList([0, "a" * 10000])

        def pusher_sideeffect(*args, **kwargs):
            """Set return value and collect args/kwargs."""
            shared_list[0] += 1
            kwargs_copy = copy.deepcopy(kwargs)
            for k, v in kwargs_copy.items():
                if isinstance(kwargs_copy[k], bytes):
                    kwargs_copy[k] = v.decode()
                if isinstance(kwargs_copy[k], azm.Source):
                    kwargs_copy[k] = kwargs_copy[k].model_dump_json()
                if isinstance(kwargs_copy[k], azm.FileInfo):
                    kwargs_copy[k] = kwargs_copy[k].model_dump_json()
            # Drop the storage proxy files.
            kwargs_copy.pop("local")
            try:
                print(json.dumps(kwargs_copy))
            except Exception as e:
                print("Shared list exception occurred: ", e)
            shared_list[1] = json.dumps(kwargs_copy)

        self.mock_pusher.push_once_sourced.side_effect = pusher_sideeffect

        self.client = get_app(self.mock_pusher)

        response: httpx.Response = self.client.post("", json=action)
        print(response.content)
        self.assertEqual(200, response.status_code)

        # Note below asserts have commented above them the normal equivalent if shared memory
        # didn't have to be used to get data out of the subprocess

        # Should be 1 call for the root file being downloaded and then pushed
        self.assertEqual(download_shared_list[0], 1)
        self.assertEqual(shared_list[0], 1)

        # Verify first call argument is correct
        # args, kwargs = self.mock_pusher.push_once.call_args
        kwargs = json.loads(shared_list[1])

        print("expected\n", kwargs, "\nend expected")
        self.assertEqual(
            kwargs,
            {
                "content": "content",
                "source_label": "assemblyline",
                "references": {"type": "USER", "description": "Inspection", "user": "auser"},
                "security": "OFFICIAL TLP:CLEAR",
                "filename": "tester.zip",
            },
        )
