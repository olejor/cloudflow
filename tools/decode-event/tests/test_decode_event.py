"""pytest coverage for cloudflow-decode-event (docs/design/05-tools-tests-ci.md,
WP-13 acceptance criteria):

- ``--file`` on an event built directly with the Python bindings matches
  ``MessageToDict(preserving_proto_field_name=True)``, the same rule WP-12
  uses; ``--hec`` output on the same event equals
  ``cloudflow_sink_splunk.transform``'s own output byte-for-byte (imported,
  never duplicated -- see ``cloudflow_decode_event/_bootstrap.py``).
- argument-error handling: bad flag combinations exit nonzero and never
  touch Redis or stdin.
- decode-failure path: garbage bytes exit nonzero, print the protobuf error
  plus a hex dump of the first 64 bytes to stderr, and print nothing
  decodable to stdout.
"""

from __future__ import annotations

import json

from cloudflow.v1 import common_pb2, dhcp_pb2
from cloudflow.v1.envelope_pb2 import CloudFlowEvent
from cloudflow_sink_splunk import config as sink_config
from cloudflow_sink_splunk import transform as sink_transform
from google.protobuf import json_format

from cloudflow_decode_event import cli

STREAM_NAME = "cloudflow:v1:wire:dhcpv4"
GROUP = "sink-splunk"


def _build_event() -> CloudFlowEvent:
    """A representative DHCPv4 DISCOVER, built directly with the generated
    bindings (WP-06/07 fixture round-trip binaries have not landed; this
    mirrors the pattern sinks/cloudflow-sink-splunk/tests/fixtures.py uses
    for the same reason).
    """
    envelope = common_pb2.EventEnvelope(
        event_id="deadbeefdeadbeefdeadbeefdeadbeef",
        schema_version=1,
        source_type="dhcpv4",
        source_host="dhcp-source-01.example.net",
        source_instance="dhcp-source-01",
        capture_interface="eth0",
        observation_method="rxring",
        observed_time_unix_nano=1_730_000_000_123_456_789,
        ingest_time_unix_nano=1_730_000_000_623_456_789,
        event_type="dhcpv4.discover.observed",
        visibility=common_pb2.VISIBILITY_PACKET_PAYLOAD,
        confidence=common_pb2.OBSERVATION_CONFIDENCE_OBSERVED,
        payload_schema="cloudflow.v1.DhcpV4PacketEvent",
        stream_name=STREAM_NAME,
    )
    header = dhcp_pb2.DhcpV4Header(
        op=1,
        htype=1,
        hlen=6,
        hops=0,
        xid=0xDEADBEEF,
        secs=0,
        flags=0x8000,
        ciaddr="0.0.0.0",
        yiaddr="0.0.0.0",
        siaddr="0.0.0.0",
        giaddr="0.0.0.0",
        chaddr_raw=bytes.fromhex("020000000001") + b"\x00" * 10,
        chaddr_mac="02:00:00:00:00:01",
        magic_cookie_present=True,
    )
    decoded = dhcp_pb2.DhcpV4DecodedOptions(
        message_type=dhcp_pb2.DhcpV4DecodedOptions.DISCOVER,
        message_type_name="DISCOVER",
        parameter_request_list=[1, 3, 6, 15],
        max_dhcp_message_size=1500,
    )
    packet = common_pb2.PacketObservation(
        observed_time_unix_nano=1_730_000_000_123_456_789,
        capture_direction=common_pb2.CAPTURE_DIRECTION_INGRESS,
        link=common_pb2.LinkLayerObservation(
            src_mac="02:00:00:00:00:01",
            dst_mac="ff:ff:ff:ff:ff:ff",
            vlan_ids=[100],
            ethertype=0x0800,
        ),
        network=common_pb2.NetworkLayerObservation(
            protocol=common_pb2.NetworkLayerObservation.NETWORK_PROTOCOL_IPV4,
            src_ip="198.51.100.10",
            dst_ip="255.255.255.255",
            next_header=17,
            ttl_or_hop_limit=64,
        ),
        transport=common_pb2.TransportLayerObservation(
            protocol=common_pb2.TransportLayerObservation.TRANSPORT_PROTOCOL_UDP,
            ip_protocol_number=17,
            src_port=68,
            dst_port=67,
        ),
        packet_len=342,
        captured_len=342,
    )
    packet_event = dhcp_pb2.DhcpV4PacketEvent(packet=packet, header=header, decoded=decoded)
    return CloudFlowEvent(envelope=envelope, dhcpv4_packet=packet_event)


def _event_file(tmp_path):
    event = _build_event()
    path = tmp_path / "event.bin"
    path.write_bytes(event.SerializeToString())
    return path, event


# -- --file: JSON output matches MessageToDict --------------------------------


def test_file_json_matches_message_to_dict(tmp_path, capsys):
    path, event = _event_file(tmp_path)

    exit_code = cli.run(["--file", str(path)])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.err == ""
    assert json.loads(captured.out) == json_format.MessageToDict(event, preserving_proto_field_name=True)


# -- --hec: output equals cloudflow_sink_splunk.transform's own output --------


def test_file_hec_matches_sink_transform_output(tmp_path, capsys):
    path, event = _event_file(tmp_path)

    exit_code = cli.run(["--file", str(path), "--hec"])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.err == ""

    splunk_cfg = sink_config.SplunkConfig(
        hec_url="unused",
        hec_token_env="UNUSED_ENV_VAR",
        index="",
        sourcetypes={},
        include_raw_payload=False,
    )
    expected = sink_transform.render_hec_line(event, event.envelope.stream_name, splunk_cfg)
    assert captured.out.rstrip("\n") == expected


# -- argument-error handling ---------------------------------------------------


def test_id_without_stream_is_argument_error(capsys):
    exit_code = cli.run(["--id", "123-0"])
    captured = capsys.readouterr()
    assert exit_code == cli.EXIT_ARGS
    assert "--stream" in captured.err


def test_stream_without_id_or_last_is_argument_error(capsys):
    exit_code = cli.run(["--stream", STREAM_NAME])
    captured = capsys.readouterr()
    assert exit_code == cli.EXIT_ARGS
    assert "--id" in captured.err or "--last" in captured.err


def test_id_and_last_together_is_argument_error(capsys):
    exit_code = cli.run(["--stream", STREAM_NAME, "--id", "1-0", "--last", "5"])
    captured = capsys.readouterr()
    assert exit_code == cli.EXIT_ARGS
    assert "mutually exclusive" in captured.err


def test_file_and_stream_together_is_argument_error(tmp_path, capsys):
    path = tmp_path / "x.bin"
    path.write_bytes(b"\x00")
    exit_code = cli.run(["--file", str(path), "--stream", STREAM_NAME, "--id", "1-0"])
    captured = capsys.readouterr()
    assert exit_code == cli.EXIT_ARGS
    assert "--file" in captured.err


def test_negative_last_is_argument_error(capsys):
    exit_code = cli.run(["--stream", STREAM_NAME, "--last", "-1"])
    captured = capsys.readouterr()
    assert exit_code == cli.EXIT_ARGS


def test_missing_file_is_operational_error_not_decode_failure(tmp_path, capsys):
    missing = tmp_path / "does-not-exist.bin"
    exit_code = cli.run(["--file", str(missing)])
    captured = capsys.readouterr()
    assert exit_code == cli.EXIT_OPERATIONAL
    assert captured.out == ""


# -- decode-failure path: garbage bytes ----------------------------------------


def test_decode_failure_prints_hexdump_and_exits_nonzero(tmp_path, capsys):
    garbage = bytes([0xFF]) * 64
    path = tmp_path / "garbage.bin"
    path.write_bytes(garbage)

    exit_code = cli.run(["--file", str(path)])
    captured = capsys.readouterr()

    assert exit_code == cli.EXIT_DECODE_FAILURE
    assert captured.out == ""  # nothing decodable on stdout
    assert "ff ff ff ff" in captured.err
    assert "decode error" in captured.err.lower()


def test_decode_failure_hexdump_caps_at_64_bytes(tmp_path, capsys):
    garbage = bytes([0xAB]) * 200
    path = tmp_path / "garbage.bin"
    path.write_bytes(garbage)

    exit_code = cli.run(["--file", str(path)])
    captured = capsys.readouterr()

    assert exit_code == cli.EXIT_DECODE_FAILURE
    assert "(200 bytes total)" in captured.err
    # 64 bytes = 4 rows of 16 in the hex dump.
    assert captured.err.count("ab ab ab ab") == 4 * 4


# -- --stream / --id and --stream / --last against a real Redis ---------------


def _xadd_event(redis_client, stream, cf_event):
    return redis_client.xadd(
        stream,
        {
            "schema": "cloudflow.v1.CloudFlowEvent",
            "version": "1",
            "encoding": "protobuf",
            "payload": cf_event.SerializeToString(),
        },
    )


def test_stream_id_mode_against_real_redis(redis_server, redis_client, capsys):
    event = _build_event()
    entry_id = _xadd_event(redis_client, STREAM_NAME, event)

    exit_code = cli.run(
        [
            "--redis",
            f"{redis_server['host']}:{redis_server['port']}",
            "--stream",
            STREAM_NAME,
            "--id",
            entry_id.decode(),
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 0
    assert json.loads(captured.out) == json_format.MessageToDict(event, preserving_proto_field_name=True)


def test_stream_last_mode_against_real_redis(redis_server, redis_client, capsys):
    first = _build_event()
    first.envelope.event_id = "11111111111111111111111111111111"
    second = _build_event()
    second.envelope.event_id = "22222222222222222222222222222222"
    _xadd_event(redis_client, STREAM_NAME, first)
    _xadd_event(redis_client, STREAM_NAME, second)

    exit_code = cli.run(
        [
            "--redis",
            f"{redis_server['host']}:{redis_server['port']}",
            "--stream",
            STREAM_NAME,
            "--last",
            "2",
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 0
    # XREVRANGE returns newest-first: `second` should appear before `first`.
    assert captured.out.index('"22222222') < captured.out.index('"11111111')


def test_stream_missing_entry_id_is_operational_error(redis_server, redis_client, capsys):
    exit_code = cli.run(
        [
            "--redis",
            f"{redis_server['host']}:{redis_server['port']}",
            "--stream",
            STREAM_NAME,
            "--id",
            "999999999999-0",
        ]
    )
    captured = capsys.readouterr()
    assert exit_code == cli.EXIT_OPERATIONAL
    assert captured.out == ""
