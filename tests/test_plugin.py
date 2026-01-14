"""Test cases for plugin output."""

import json
from unittest import mock

from azul_bedrock import models_network as azm
from azul_runner import (
    FV,
    Event,
    EventData,
    EventParent,
    JobResult,
    State,
    test_template,
)

from azul_plugin_assemblyline.plugin import AzulPluginAssemblyline, common
from azul_plugin_assemblyline.settings import Settings as alSettings
from tests.support import resetEnv


class TestExecute(test_template.TestPlugin):
    PLUGIN_TO_TEST = AzulPluginAssemblyline

    def setUp(self):
        resetEnv()
        # Mock Assemblyline client to prevent the init of the plugin from failing.
        self.original_setup_client = common.setup_al_client
        self.original_download_uncarted_al_file = common.download_uncarted_al_file
        self.mock_al_client = mock.MagicMock()
        self.mock_download_uncarted_al_file = mock.MagicMock()
        common.setup_al_client = self.mock_al_client
        common.download_uncarted_al_file = self.mock_download_uncarted_al_file
        return super().setUp()

    def tearDown(self):
        common.setup_al_client = self.original_setup_client
        common.download_uncarted_al_file = self.original_download_uncarted_al_file

    def test_bad_version(self):
        """Test an expected normal run"""
        assemblyline = json.dumps(
            {
                "version": 2,
                "bad_keys": [],
            }
        ).encode()
        result = self.do_execution(data_in=[(azm.DataLabel.ASSEMBLYLINE, assemblyline)], no_multiprocessing=True)
        self.assertEqual(result.state.label, State.Label.ERROR_EXCEPTION)
        self.assertEqual(result.state.failure_name, "ServerVersionException")

    def test_execute1(self):
        """Test an expected normal run"""
        self.mock_download_uncarted_al_file.return_value = b"mock-child-binary-contents"
        assemblyline = self.load_local_raw(
            "sample1", "assemblyline.json", description="Json output of a sample that was passed into Assemblyline."
        )
        result = self.do_execution(data_in=[(azm.DataLabel.ASSEMBLYLINE, assemblyline)], no_multiprocessing=True)
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        sha256="test_entity",
                        features={
                            "assemblyline_score": [FV("0")],
                            "assemblyline_type": [FV("archive/zip")],
                            "filename": [FV("tester.zip")],
                            "heuristic": [FV("Extracted from archive", label="EXTRACT_1 | score 0")],
                        },
                    ),
                    Event(
                        sha256="98f940cb17165e4c855051c4e8e2bdd4a8d5e171a008febdad2ecdd8240750e2",
                        sha1="58a62baa66adf24fedf2f87f83768424b9520734",
                        md5="4b04dfea90a8554d3c1f0a668b45fc4c",
                        size=631,
                        file_format="archive/zip",
                        mime="application/zip",
                        magic="Zip archive data, at least v2.0 to extract",
                        parent=EventParent(sha256="test_entity", filename="tester.zip"),
                        relationship={"action": "Extract", "note": "extract_zip"},
                        data=[
                            EventData(
                                hash="0d2dcab5a83fd33570350a27d8acfe8a98276c607472b159c8af85f382b850b7",
                                label="content",
                            )
                        ],
                        features={
                            "assemblyline_type": [FV("archive/zip")],
                            "filename": [FV("tester/nested.zip")],
                            "heuristic": [FV("Extracted from archive", label="EXTRACT_1 | score 0")],
                        },
                    ),
                    Event(
                        sha256="e6dfab4aa1338811a8d679c4b9edb7291f3bbf493fa4f6b3da922ef82a4e3844",
                        sha1="59e5257a0a9579729158448d6eb947259b6900b5",
                        md5="a21ec7e3ff690fa14c75c0372a613906",
                        size=21,
                        file_format="text/plain",
                        mime="text/plain",
                        magic="ASCII text, with no line terminators",
                        parent=EventParent(
                            sha256="98f940cb17165e4c855051c4e8e2bdd4a8d5e171a008febdad2ecdd8240750e2",
                            sha1="58a62baa66adf24fedf2f87f83768424b9520734",
                            md5="4b04dfea90a8554d3c1f0a668b45fc4c",
                            size=631,
                            file_format="archive/zip",
                            mime="application/zip",
                            magic="Zip archive data, at least v2.0 to extract",
                            parent=EventParent(sha256="test_entity", filename="tester.zip"),
                            relationship={"action": "Extract", "note": "extract_zip"},
                            filename="tester/nested.zip",
                        ),
                        relationship={"action": "Extract", "note": "extract_zip"},
                        data=[
                            EventData(
                                hash="0d2dcab5a83fd33570350a27d8acfe8a98276c607472b159c8af85f382b850b7",
                                label="content",
                            )
                        ],
                        features={
                            "assemblyline_type": [FV("archive/zip"), FV("text/plain")],
                            "filename": [FV("tester/file1.txt"), FV("tester/metronome.zip")],
                            "heuristic": [FV("Extracted from archive", label="EXTRACT_1 | score 0")],
                        },
                    ),
                    Event(
                        sha256="a495a4b86c1eac64327d8cad2598044314d9176f0ac069fbea0cf0baf08b6c9b",
                        sha1="e029e41f4e015e2ea604a0d81a05a05186f15b03",
                        md5="29814d7ba6b9db8d5ab57fd57ceb9c1a",
                        size=4,
                        file_format="text/plain",
                        mime="text/plain",
                        magic="ASCII text, with no line terminators",
                        parent=EventParent(
                            sha256="72ca8fc6d0e6d84ac70464d34a701e60d28b2c93dc6f955b7635816e14199ce4",
                            sha1="8d5d39f6b8757d3bab35b34ada30d74d3629e139",
                            md5="4d4ca18aed6c4a3878fffa80fdeb1874",
                            size=134,
                            file_format="archive/zip",
                            mime="application/zip",
                            magic="Zip archive data, at least v2.0 to extract",
                            parent=EventParent(
                                sha256="98f940cb17165e4c855051c4e8e2bdd4a8d5e171a008febdad2ecdd8240750e2",
                                sha1="58a62baa66adf24fedf2f87f83768424b9520734",
                                md5="4b04dfea90a8554d3c1f0a668b45fc4c",
                                size=631,
                                file_format="archive/zip",
                                mime="application/zip",
                                magic="Zip archive data, at least v2.0 to extract",
                                parent=EventParent(sha256="test_entity", filename="tester.zip"),
                                relationship={"action": "Extract", "note": "extract_zip"},
                                filename="tester/nested.zip",
                            ),
                            relationship={"action": "Extract", "note": "extract_zip"},
                            filename="tester/metronome.zip",
                        ),
                        relationship={"action": "Extract", "note": "extract_zip"},
                        data=[
                            EventData(
                                hash="0d2dcab5a83fd33570350a27d8acfe8a98276c607472b159c8af85f382b850b7",
                                label="content",
                            )
                        ],
                        features={
                            "assemblyline_type": [FV("text/plain")],
                            "filename": [FV("tester/things/orbit.txt"), FV("things/orbit.txt")],
                        },
                    ),
                ],
                data={"0d2dcab5a83fd33570350a27d8acfe8a98276c607472b159c8af85f382b850b7": b""},
            ),
        )

    def test_execute1_originating_from_azul(self):
        """Test an expected normal run but the file was originally from azul."""
        self.mock_download_uncarted_al_file.return_value = b"mock-child-binary-contents"
        assemblyline = self.load_local_raw(
            "sample1", "assemblyline.json", description="Json output of a sample that was passed into Assemblyline."
        )
        # Mark as originally from azul
        assemblyline = json.loads(assemblyline.decode())
        assemblyline["action"]["submission"]["metadata"] = {alSettings().azul_instance_key: alSettings().azul_instance}
        assemblyline = json.dumps(assemblyline)
        result = self.do_execution(
            data_in=[(azm.DataLabel.ASSEMBLYLINE, assemblyline.encode())], no_multiprocessing=True
        )
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        sha256="test_entity",
                        features={
                            "assemblyline_score": [FV("0")],
                            "assemblyline_type": [FV("archive/zip")],
                            "filename": [FV("tester.zip")],
                            "heuristic": [FV("Extracted from archive", label="EXTRACT_1 | score 0")],
                        },
                    )
                ],
            ),
        )

        self.mock_download_uncarted_al_file.return_value = b"mock-child-binary-contents"
        assemblyline = self.load_local_raw(
            "sample1", "assemblyline.json", description="Json output of a sample that was passed into Assemblyline."
        )
        # Mark as originally from azul
        assemblyline = json.loads(assemblyline.decode())
        assemblyline["action"]["submission"]["metadata"] = {alSettings().azul_instance_key: "bingus"}
        assemblyline = json.dumps(assemblyline)
        result = self.do_execution(
            data_in=[(azm.DataLabel.ASSEMBLYLINE, assemblyline.encode())], no_multiprocessing=True
        )
        self.assertJobResult(
            result,
            JobResult(state=State(State.Label.OPT_OUT, message="report from azul instance 'bingus' not 'azul'")),
        )

    def test_execute2(self):
        """Test an expected normal run"""
        self.mock_download_uncarted_al_file.return_value = b"mock-child-binary-contents for second example"
        assemblyline = self.load_local_raw(
            "sample2", "assemblyline.json", description="Json output of a sample that was passed into Assemblyline."
        )
        result = self.do_execution(data_in=[(azm.DataLabel.ASSEMBLYLINE, assemblyline)], no_multiprocessing=True)
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        sha256="test_entity",
                        features={
                            "assemblyline_score": [FV("650")],
                            "assemblyline_type": [FV("archive/zip")],
                            "filename": [FV("content.cart")],
                            "heuristic": [
                                FV("Extracted from Protected Archive", label="EXTRACT_10 | score 0"),
                                FV(
                                    "Suspicious combination of executables in Archive File",
                                    label="EXTRACT_16 | score 500",
                                ),
                            ],
                            "password": [FV("infected")],
                        },
                    ),
                    Event(
                        sha256="e0ca8a51004c4f2ccd2caa2f04626fa9497209be6c58f0f6bef6784640cf81f0",
                        sha1="45a39c509a255851e9eaa6b32b19c8719ec3eb2e",
                        md5="03a0cbf61e478d71c6345bda66a01a6a",
                        size=12721664,
                        file_format="executable/windows/pe32",
                        mime="application/vnd.microsoft.portable-executable",
                        magic="PE32 executable (GUI) Intel 80386, for MS Windows, 4 sections",
                        parent=EventParent(sha256="test_entity", filename="content.cart"),
                        relationship={"action": "Extract", "note": "extract_zip_7zip"},
                        data=[
                            EventData(
                                hash="cfacb9d1375039214d912fee683e0a59d449d3e1323bb5e156f246b6a4beba4a",
                                label="content",
                            )
                        ],
                        features={
                            "assemblyline_type": [FV("document/pdf"), FV("executable/windows/pe32")],
                            "filename": [FV("FaaLZsPl.exe"), FV("jOOvKQwn.exe")],
                            "heuristic": [
                                FV("Extracted from executable", label="EXTRACT_2 | score 0"),
                                FV("Invalid optional header checksum", label="PE_23 | score 0"),
                                FV("Mismatch file size", label="PE_24 | score 0"),
                                FV("Multiple different non-zero timestamps", label="PE_11 | score 250"),
                                FV("No relocations found", label="PE_37 | score 50"),
                                FV("PE file has non-.text section that is executable", label="PE_33 | score 0"),
                                FV("Unknown Root CA", label="PE_5 | score 100"),
                            ],
                            "pe_export": [FV("hovaf.exe")],
                            "pe_export_function": [FV("@Summary@16")],
                            "pe_import_hash_sorted": [
                                FV("28a099a911237a28521d8b7ea250f089"),
                                FV("3e7553c67a710a49ecfb599afe1ce756"),
                                FV("9a328f289a877a8bb21c4447b0190d39"),
                                FV("a56705099ec07c676809955bdcce8d09"),
                            ],
                            "pe_section": [
                                FV(".bss"),
                                FV(".data"),
                                FV(".idata"),
                                FV(".ndata"),
                                FV(".rdata"),
                                FV(".reloc"),
                                FV(".rsrc"),
                                FV(".text"),
                                FV("dhxsdxs"),
                            ],
                            "pe_section_hash": [
                                FV("0441120305f37e7433f56eed779458cc"),
                                FV("0d970ac66226d425e01c9de37cbf6845"),
                                FV("0deff3e179a4348a5eba2c4086719649"),
                                FV("0f343b0931126a20f133d67c2b018a3b"),
                                FV("1f30040a7913f120d39dd1752a9cb2a8"),
                                FV("33d27a2fae9af0a905e04f435ffb6b93"),
                                FV("6687ba59b5d38e4bf682cb89d1ad1caf"),
                                FV("6a948911f672fc237b363cdc83e15500"),
                                FV("93ed171e24c0d9be6c0320c819f41425"),
                                FV("9b92804c9f17d482b8e1e62c985382e0"),
                                FV("b0662bbe3b137c142d2ce50e9096a14c"),
                                FV("b613839138a7e035f726926e709fbe52"),
                                FV("c12835d0f68f00f620859ad48376699e"),
                                FV("cb35e03cb1836d9c3974ad724a8cc88b"),
                                FV("d41d8cd98f00b204e9800998ecf8427e"),
                            ],
                        },
                    ),
                    Event(
                        sha256="2eaeaf5b43dbebef1982a6ffab12b4f6d2f9f7b9e3aa3afa324dad123daf6e62",
                        sha1="eceea561949ba95a954f40c3fda5849927bf2382",
                        md5="c12835d0f68f00f620859ad48376699e",
                        size=7680,
                        file_format="unknown",
                        mime="application/octet-stream",
                        magic="data",
                        parent=EventParent(
                            sha256="aa3de83e4d18b1fc7d2e051d39ea21dbf2b3404a295b2e49b8cc2cae993ec97e",
                            sha1="06ecff4f7c6ff69e7049920d2a9e182bace86a32",
                            md5="350d38918a181c4e77713cc566440376",
                            size=504088,
                            file_format="executable/windows/pe32",
                            mime="application/vnd.microsoft.portable-executable",
                            magic="PE32 executable (GUI) Intel 80386 (stripped to external PDB), for MS Windows, Nullsoft Installer self-extracting archive, 7 sections",
                            parent=EventParent(sha256="test_entity", filename="content.cart"),
                            relationship={"action": "Extract", "note": "extract_zip_7zip"},
                            filename="FaaLZsPl.exe",
                        ),
                        relationship={"action": "Extract", "note": "extract_zip_7zip"},
                        data=[
                            EventData(
                                hash="cfacb9d1375039214d912fee683e0a59d449d3e1323bb5e156f246b6a4beba4a",
                                label="content",
                            )
                        ],
                        features={
                            "assemblyline_type": [
                                FV("archive/nsis"),
                                FV("executable/windows/dll32"),
                                FV("executable/windows/pe32"),
                                FV("unknown"),
                            ],
                            "filename": [
                                FV("$PLUGINSDIR/GetVersion.dll"),
                                FV("$PLUGINSDIR/NSISdl.dll"),
                                FV("$PLUGINSDIR/Processes.dll"),
                                FV("$PLUGINSDIR/nsExec.dll"),
                                FV("$TEMP/520bdc5a5365af473043c9baa03bba8c/downloaderDDLR.exe"),
                                FV("$TEMP/520bdc5a5365af473043c9baa03bba8c/downloaderOFFER0.exe"),
                                FV("$TEMP/520bdc5a5365af473043c9baa03bba8c/downloaderOFFER1.exe"),
                                FV("$TEMP/520bdc5a5365af473043c9baa03bba8c/downloaderOFFER2.exe"),
                                FV("$TEMP/520bdc5a5365af473043c9baa03bba8c/downloaderSTUB.exe"),
                                FV("$TEMP/520bdc5a5365af473043c9baa03bba8c/preinstaller.exe"),
                                FV(".data"),
                                FV("GetVersion.dll"),
                                FV("Processes.dll"),
                                FV("overlay"),
                            ],
                            "heuristic": [
                                FV("Extracted from executable", label="EXTRACT_2 | score 0"),
                                FV("High section entropy", label="PE_4 | score 100"),
                                FV("Mismatch file size", label="PE_24 | score 0"),
                                FV("No relocations found", label="PE_37 | score 50"),
                                FV("PE file does not contain any resources", label="PE_35 | score 100"),
                                FV("Single Executable Inside Archive File", label="EXTRACT_13 | score 500"),
                                FV("Unknown Root CA", label="PE_5 | score 100"),
                            ],
                            "pe_export": [
                                FV("GetVersion.dll"),
                                FV("NSISdl.dll"),
                                FV("Processes.dll"),
                                FV("nsExec.dll"),
                            ],
                            "pe_export_function": [
                                FV("Exec"),
                                FV("ExecToLog"),
                                FV("ExecToStack"),
                                FV("FindDevice"),
                                FV("FindProcess"),
                                FV("KillProcess"),
                                FV("WindowsName"),
                                FV("WindowsPlatformArchitecture"),
                                FV("WindowsPlatformId"),
                                FV("WindowsServerName"),
                                FV("WindowsServicePack"),
                                FV("WindowsServicePackBuild"),
                                FV("WindowsServicePackMajor"),
                                FV("WindowsServicePackMinor"),
                                FV("WindowsType"),
                                FV("WindowsVersion"),
                                FV("download"),
                                FV("download_quiet"),
                            ],
                            "pe_import_hash_sorted": [
                                FV("06e07a9e2c8ec78ec44f1a538a1bd2a2"),
                                FV("6c01223cb63ee4264a1cff8d0322dcde"),
                                FV("7fa974366048f9c551ef45714595665e"),
                                FV("c75aa021b4be3f016821b31d91352687"),
                                FV("f5edecae12589e705677a6e272ad0394"),
                                FV("fb1aa2bbc159c94cb45792330366bd5f"),
                            ],
                            "pe_section": [
                                FV(".CRT"),
                                FV(".bss"),
                                FV(".data"),
                                FV(".edata"),
                                FV(".idata"),
                                FV(".ndata"),
                                FV(".rdata"),
                                FV(".reloc"),
                                FV(".rsrc"),
                                FV(".text"),
                                FV(".tls"),
                            ],
                            "pe_section_hash": [
                                FV("02615cd59c9695fa6ea2419707fc751d"),
                                FV("15084355404e89cc27e38b1ffd446c4c"),
                                FV("18c12a89d7cc83868e420a7db6765af1"),
                                FV("1e2b81ead0f4751f7c8baa09d420c54d"),
                                FV("2360aaea431da381f508228c0e44819f"),
                                FV("3f9596a3d74196ec7b6e4414efb759f6"),
                                FV("400838b5b55207fe8b1e65fb997017c9"),
                                FV("4b35941436daea46775df93d51ad2732"),
                                FV("6d1a71824e031acb65b964eca42d6499"),
                                FV("719054c0d2354b37f1d79c7b31ca1f09"),
                                FV("916da0aa22a056c132567a13e1bfd380"),
                                FV("9392878d5fa3dc299ab7d7ad692e790e"),
                                FV("9506db59fc8207dabe7547cb118f380b"),
                                FV("9df279324ae2a4faaccc978d92c5e181"),
                                FV("9f44510155fcc875698d0faff8b7f0e6"),
                                FV("a2c7710fa66fcbb43c7ef0ab9eea5e9a"),
                                FV("ac164d59e6234015cfd24e6d492ca333"),
                                FV("acea0db78a90f312bfe755b81f498ff7"),
                                FV("b0df6024ced7323a110ae9324d526f17"),
                                FV("b8d87c1578e61c780e59b30531bb88db"),
                                FV("bae225a645703e82ce8c702fdf1a65c8"),
                                FV("bb63fc88e24e669cc841d5262afd7ae1"),
                                FV("beaba0af8b0070f00cd0e5cd3d6ce60c"),
                                FV("bf32ae10a450bbafd895f9c66ae608b3"),
                                FV("c468346706531559b5603752b7c239e1"),
                                FV("c69726ed422d3dcfdec9731986daa752"),
                                FV("d41d8cd98f00b204e9800998ecf8427e"),
                                FV("d59a8b8e6667086aebd321f679425a77"),
                                FV("dd3e8c6429a9b7a87e66685ef929647a"),
                                FV("e59cdcb732e4bfbc84cc61dd68354f78"),
                                FV("f1c6f45070673f3c80777dd7fcedec8e"),
                                FV("f4d0b25400864bbacf759d338d135527"),
                                FV("f890fb635b464cf4fa4e61e4de0e2400"),
                            ],
                        },
                    ),
                    Event(
                        sha256="dacc88a12d3ba438fdae3535dc7a5a1d389bce13adc993706424874a782e51c9",
                        sha1="168f3c158913b0367bf79fa413357fbe97018191",
                        md5="a5f8399a743ab7f9c88c645c35b1ebb5",
                        size=14848,
                        file_format="executable/windows/dll32",
                        mime="application/vnd.microsoft.portable-executable",
                        magic="PE32 executable (DLL) (GUI) Intel 80386, for MS Windows, 4 sections",
                        parent=EventParent(
                            sha256="19460c3c1b450286c68fba77086c561e740374ae5c44213dd2ec22dc52a430b8",
                            sha1="9161574590f09cfe4c24498827386ed57f2e8c58",
                            md5="06baef00ae0f0e42fc5fea24fc4eac42",
                            size=218624,
                            file_format="executable/windows/pe32",
                            mime="application/vnd.microsoft.portable-executable",
                            magic="PE32 executable (GUI) Intel 80386 (stripped to external PDB), for MS Windows, 8 sections",
                            parent=EventParent(
                                sha256="aa3de83e4d18b1fc7d2e051d39ea21dbf2b3404a295b2e49b8cc2cae993ec97e",
                                sha1="06ecff4f7c6ff69e7049920d2a9e182bace86a32",
                                md5="350d38918a181c4e77713cc566440376",
                                size=504088,
                                file_format="executable/windows/pe32",
                                mime="application/vnd.microsoft.portable-executable",
                                magic="PE32 executable (GUI) Intel 80386 (stripped to external PDB), for MS Windows, Nullsoft Installer self-extracting archive, 7 sections",
                                parent=EventParent(sha256="test_entity", filename="content.cart"),
                                relationship={"action": "Extract", "note": "extract_zip_7zip"},
                                filename="FaaLZsPl.exe",
                            ),
                            relationship={"action": "Extract", "note": "extract_zip_7zip"},
                            filename="$TEMP/520bdc5a5365af473043c9baa03bba8c/preinstaller.exe",
                        ),
                        relationship={"action": "PE", "note": "overlay extracted from binary's resources"},
                        data=[
                            EventData(
                                hash="cfacb9d1375039214d912fee683e0a59d449d3e1323bb5e156f246b6a4beba4a",
                                label="content",
                            )
                        ],
                        features={
                            "assemblyline_type": [
                                FV("archive/nsis"),
                                FV("certificate/rsa"),
                                FV("executable/windows/dll32"),
                                FV("unknown"),
                            ],
                            "filename": [
                                FV("$PLUGINSDIR/NSISdl.dll"),
                                FV(".CRT"),
                                FV(".data"),
                                FV(".edata"),
                                FV(".tls"),
                                FV("CERTIFICATE"),
                                FV("overlay"),
                            ],
                            "heuristic": [
                                FV("Extracted from archive", label="EXTRACT_1 | score 0"),
                                FV("Extracted from executable", label="EXTRACT_2 | score 0"),
                                FV("Mismatch file size", label="PE_24 | score 0"),
                                FV("PE file does not contain any resources", label="PE_35 | score 100"),
                            ],
                            "pe_export": [FV("NSISdl.dll")],
                            "pe_export_function": [FV("download"), FV("download_quiet")],
                            "pe_import_hash_sorted": [FV("9cce555dd3ff1b6c7dc92d64c794c51a")],
                            "pe_section": [FV(".data"), FV(".rdata"), FV(".reloc"), FV(".text")],
                            "pe_section_hash": [
                                FV("01e85bb88c8a4f42be091c6a5773f638"),
                                FV("147ecd99b82beedf094c555415e640b3"),
                                FV("9f74e0a7eb25574e64a2958b8dbb8a38"),
                                FV("ef9faf874ba1ca1a120aa55a00a1c3a9"),
                            ],
                        },
                    ),
                    Event(
                        sha256="d3eddba2a4f05a868e6f657b7a8cb4dea830703701c82202d3e5c71c4b9f5b47",
                        sha1="30b289e09fbc61eb6d29169b4ee9f9b9910b7bd9",
                        md5="01e85bb88c8a4f42be091c6a5773f638",
                        size=1536,
                        file_format="unknown",
                        mime="application/octet-stream",
                        magic="data",
                        parent=EventParent(
                            sha256="10f3bf0bb5ee4c99f505224c9c398a4a0b3f7aaa92e0cf4776d1f2f26df0e47d",
                            sha1="5745e43a3244daa94179641acb99ffbc7e92b570",
                            md5="57ff26bb5db2cfc64c2beffd031132fd",
                            size=14584,
                            file_format="archive/nsis",
                            mime="application/octet-stream",
                            magic="custom: archive/nsis",
                            parent=EventParent(
                                sha256="19460c3c1b450286c68fba77086c561e740374ae5c44213dd2ec22dc52a430b8",
                                sha1="9161574590f09cfe4c24498827386ed57f2e8c58",
                                md5="06baef00ae0f0e42fc5fea24fc4eac42",
                                size=218624,
                                file_format="executable/windows/pe32",
                                mime="application/vnd.microsoft.portable-executable",
                                magic="PE32 executable (GUI) Intel 80386 (stripped to external PDB), for MS Windows, 8 sections",
                                parent=EventParent(
                                    sha256="aa3de83e4d18b1fc7d2e051d39ea21dbf2b3404a295b2e49b8cc2cae993ec97e",
                                    sha1="06ecff4f7c6ff69e7049920d2a9e182bace86a32",
                                    md5="350d38918a181c4e77713cc566440376",
                                    size=504088,
                                    file_format="executable/windows/pe32",
                                    mime="application/vnd.microsoft.portable-executable",
                                    magic="PE32 executable (GUI) Intel 80386 (stripped to external PDB), for MS Windows, Nullsoft Installer self-extracting archive, 7 sections",
                                    parent=EventParent(sha256="test_entity", filename="content.cart"),
                                    relationship={"action": "Extract", "note": "extract_zip_7zip"},
                                    filename="FaaLZsPl.exe",
                                ),
                                relationship={"action": "Extract", "note": "extract_zip_7zip"},
                                filename="$TEMP/520bdc5a5365af473043c9baa03bba8c/preinstaller.exe",
                            ),
                            relationship={"action": "PE", "note": "overlay extracted from binary's resources"},
                            filename=".CRT",
                        ),
                        relationship={"action": "Extract", "note": "extract_nsis"},
                        data=[
                            EventData(
                                hash="cfacb9d1375039214d912fee683e0a59d449d3e1323bb5e156f246b6a4beba4a",
                                label="content",
                            )
                        ],
                        features={
                            "assemblyline_type": [FV("text/plain"), FV("unknown")],
                            "filename": [FV(".data"), FV("SETUP.nsi")],
                        },
                    ),
                ],
                data={"cfacb9d1375039214d912fee683e0a59d449d3e1323bb5e156f246b6a4beba4a": b""},
            ),
        )

    def test_yara_match_example(self):
        """Simple yara match example"""
        self.mock_download_uncarted_al_file.return_value = b"mock-child-binary-contents"
        assemblyline = self.load_local_raw(
            "sample_yara",
            "yara_result_example.json",
            description="Json output of a sample that hit a yara rule that was passed into Assemblyline.",
        )
        # ent_id is required to get yara results, it's been set to the sha256 of the sample submitted to AL to get the example AL metadata
        result = self.do_execution(
            ent_id="717b6d2d0e4f17cccd8fd0f3c05efc6d2e7c7a30dd323eb676622d67d06bc14f",
            data_in=[(azm.DataLabel.ASSEMBLYLINE, assemblyline)],
            no_multiprocessing=True,
        )
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        sha256="717b6d2d0e4f17cccd8fd0f3c05efc6d2e7c7a30dd323eb676622d67d06bc14f",
                        features={
                            "assemblyline_score": [FV("1000")],
                            "assemblyline_type": [FV("executable/windows/dos")],
                            "heuristic": [FV("Malware", label="YARA_5 | score 1000")],
                            "yara_match": [
                                FV("'EnigmaProtector' ", label="EnigmaStub", offset=166459),
                                FV("'EnigmaProtector' ", label="EnigmaStub", offset=166481),
                                FV("'EnigmaProtector' ", label="EnigmaStub", offset=166520),
                                FV("'EnigmaProtector' ", label="EnigmaStub", offset=166553),
                                FV("'EnigmaProtector' ", label="EnigmaStub", offset=166576),
                            ],
                            "yararule": [FV("bartblaze.EnigmaStub")],
                        },
                    )
                ],
            ),
        )

    def test_nested_yara_match_example(self):
        """Yara match example where the yara matches are in extracted children to ensure the matches are attributed to the appropriate binary."""
        self.mock_download_uncarted_al_file.return_value = b"mock-child-binary-contents"
        assemblyline = self.load_local_raw(
            "sample_nested_yara",
            "nested_yara_hits.json",
            description="Json output of a sample that was passed into Assemblyline and hit a nested yara rule.",
        )
        # ent_id is required to get yara results, it's been set to the sha256 of the sample submitted to AL to get the example AL metadata
        result = self.do_execution(
            ent_id="", data_in=[(azm.DataLabel.ASSEMBLYLINE, assemblyline)], no_multiprocessing=True
        )
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        sha256="",
                        features={
                            "assemblyline_score": [FV("1000")],
                            "assemblyline_type": [FV("archive/zip")],
                            "filename": [FV("parent.zip.zip")],
                            "heuristic": [FV("Extracted from archive", label="EXTRACT_1 | score 0")],
                        },
                    ),
                    Event(
                        sha256="9b79156d117425d5f16adfccd27f9d5f89c5861350b3bcc6ab9390f3f48571e5",
                        sha1="181ca669eb1e91afb4f5efc37eaf556c475e6e9a",
                        md5="40693af66361ac936bc9f59006ab1142",
                        size=82397,
                        file_format="archive/cart",
                        mime="application/octet-stream",
                        magic="custom: archive/cart",
                        parent=EventParent(sha256="", filename="parent.zip.zip"),
                        relationship={"action": "Extract", "note": "extract_zip_7zip"},
                        data=[
                            EventData(
                                hash="0d2dcab5a83fd33570350a27d8acfe8a98276c607472b159c8af85f382b850b7",
                                label="content",
                            )
                        ],
                        features={
                            "assemblyline_type": [FV("archive/cart")],
                            "filename": [FV("717b6d2d0e4f17cccd8fd0f3c05efc6d2e7c7a30dd323eb676622d67d06bc14f.cart")],
                            "heuristic": [
                                FV("Extracted from archive", label="EXTRACT_1 | score 0"),
                                FV("Single Executable Inside Archive File", label="EXTRACT_13 | score 500"),
                            ],
                        },
                    ),
                    Event(
                        sha256="717b6d2d0e4f17cccd8fd0f3c05efc6d2e7c7a30dd323eb676622d67d06bc14f",
                        sha1="0a4ed360e4e0626138d3a53032d23f705707b421",
                        md5="6f5e21db36c58892d50834f647e8a8d7",
                        size=287232,
                        file_format="executable/windows/dos",
                        mime="application/octet-stream",
                        magic="MS-DOS executable",
                        parent=EventParent(
                            sha256="9b79156d117425d5f16adfccd27f9d5f89c5861350b3bcc6ab9390f3f48571e5",
                            sha1="181ca669eb1e91afb4f5efc37eaf556c475e6e9a",
                            md5="40693af66361ac936bc9f59006ab1142",
                            size=82397,
                            file_format="archive/cart",
                            mime="application/octet-stream",
                            magic="custom: archive/cart",
                            parent=EventParent(sha256="", filename="parent.zip.zip"),
                            relationship={"action": "Extract", "note": "extract_zip_7zip"},
                            filename="717b6d2d0e4f17cccd8fd0f3c05efc6d2e7c7a30dd323eb676622d67d06bc14f.cart",
                        ),
                        relationship={"action": "Extract", "note": "extract_cart"},
                        data=[
                            EventData(
                                hash="0d2dcab5a83fd33570350a27d8acfe8a98276c607472b159c8af85f382b850b7",
                                label="content",
                            )
                        ],
                        features={
                            "assemblyline_type": [FV("executable/windows/dos")],
                            "heuristic": [FV("Malware", label="YARA_5 | score 1000")],
                            "yara_match": [
                                FV("'EnigmaProtector' ", label="EnigmaStub", offset=166459),
                                FV("'EnigmaProtector' ", label="EnigmaStub", offset=166481),
                                FV("'EnigmaProtector' ", label="EnigmaStub", offset=166520),
                                FV("'EnigmaProtector' ", label="EnigmaStub", offset=166553),
                                FV("'EnigmaProtector' ", label="EnigmaStub", offset=166576),
                            ],
                            "yararule": [FV("bartblaze.EnigmaStub")],
                        },
                    ),
                ],
                data={"0d2dcab5a83fd33570350a27d8acfe8a98276c607472b159c8af85f382b850b7": b""},
            ),
        )
