# Copyright 2021 Metaname <https://metaname.net/>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from json.decoder import JSONDecodeError
from unittest import mock
import unittest

from certbot import errors
from certbot.compat import os
from certbot.plugins import dns_test_common
from certbot.plugins.dns_test_common import DOMAIN
from certbot.tests import util as test_util

from certbot_dns_metaname import MetanameApiClient, Authenticator

account_reference = "test_account_reference"
api_key = "test_api_key"
endpoint = "http://127.0.0.1"


class FakeApiResponse:
    def __init__(self, request_endpoint, json=None):
        preamble = {"jsonrpc": "2.0", "id": json["id"]}

        if json["method"] == "price" and json["params"][2] == "example.com":
            self.response = {**preamble, "result": 999.99}
        elif json["method"] == "price" and json["params"][2] == "invalid":
            self.response = {
                **preamble,
                "error": {"message": "Invalid domain name", "code": -4},
            }
        elif json["method"] == "invalid-json":
            raise JSONDecodeError("", "", 0)
        elif json["method"] == "general-failure":
            raise Exception("")
        elif json["method"] == "wrong-sequence":
            self.response = {**preamble, "id": "invalid"}
        elif json["method"] == "undefined-response":
            self.response = {**preamble, "invalid": "invalid"}
        elif json["method"] == "dns_zones":
            self.response = {
                **preamble,
                "result": [
                    {"name": "example.com"},
                    {"name": "another-test.example.com"},
                    {"name": "example.net"},
                ],
            }
        elif json["method"] == "create_dns_record" and json["params"] == (
            "test_account_reference",
            "test_api_key",
            "example.com",
            {
                "name": "_acme-challenge.test.example.com.",
                "type": "TXT",
                "aux": None,
                "ttl": 60,
                "data": "test_validation",
            },
        ):
            self.response = {**preamble, "result": "record_reference"}
        elif json["method"] == "delete_dns_record" and json["params"] == (
            "test_account_reference",
            "test_api_key",
            "example.com",
            "record_reference",
        ):
            self.response = {**preamble, "result": {}}
        else:
            print(f"Unknown fake request: json={json}")
            self.response = {}

    def json(self):
        return self.response


def mock_api_post(*args, **kwargs):
    return FakeApiResponse(*args, **kwargs)


class ClientTest(unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.client = MetanameApiClient(
            account_reference=account_reference, api_key=api_key, endpoint=endpoint
        )

    def test_init(self):
        self.assertIsInstance(self.client, MetanameApiClient, "API client missing")
        self.assertEqual(
            self.client.session.headers["content-type"],
            "application/json",
            "default content-type header incorrect",
        )
        self.assertEqual(
            self.client.payload,
            {"jsonrpc": "2.0"},
            "incorrect jsonrpc version in payload template",
        )
        self.assertEqual(
            self.client.auth_params,
            (account_reference, api_key),
            "authentication missing from params template",
        )
        self.assertEqual(self.client.endpoint, endpoint, "custom API endpoint ignored")

    @mock.patch("certbot_dns_metaname.requests.Session.post", side_effect=mock_api_post)
    def test_request(self, mock_post):
        # API call that doesn't return JSON
        with self.assertRaises(Exception, msg="invalid JSON not caught") as cm:
            self.client.request("invalid-json")
        self.assertIn(
            "Metaname API didn't return a JSON response",
            cm.exception.args[0],
            "invalid JSON did not produce expected exception",
        )

        # API call with "result"
        self.assertIsInstance(
            self.client.request("price", "example.com", 12, False),
            float,
            "successful API response not handled",
        )

        # API call with "error"
        with self.assertRaises(Exception, msg="API error not handled") as cm:
            self.client.request("price", "invalid", 12, False)
        self.assertIn(
            "Metaname API error",
            cm.exception.args[0],
            "API error did not produce expected exception",
        )

        # requests fails entirely
        with self.assertRaises(
            Exception, msg="generic requests failure not caught"
        ) as cm:
            self.client.request("general-failure")
        self.assertIn(
            "Metaname API call failed: ",
            cm.exception.args[0],
            "generic requests failure did not produce expected exception",
        )

        # API response is out of sequence
        with self.assertRaises(
            Exception, msg="out of order API response not caught"
        ) as cm:
            self.client.request("wrong-sequence")
        self.assertIn(
            "Metaname API returned out of sequence response: ",
            cm.exception.args[0],
            "out of order API response did not produce expected exception",
        )

        # API responds but has no result or error
        with self.assertRaises(
            Exception, msg="API response containing neither result or error not caught"
        ) as cm:
            self.client.request("undefined-response")
        self.assertIn(
            "Metaname API returned an invalid response: ",
            cm.exception.args[0],
            "API response containing neither result or error did not produce expected exception",
        )


class AuthenticatorTest(
    test_util.TempDirTestCase, dns_test_common.BaseAuthenticatorTest
):
    def setUp(self):
        super().setUp()

        credentials_path = os.path.join(self.tempdir, "metaname.ini")
        dns_test_common.write(
            {
                "metaname_account_reference": account_reference,
                "metaname_api_key": api_key,
            },
            credentials_path,
        )
        config = mock.MagicMock(
            metaname_credentials=credentials_path, metaname_propagation_seconds=0
        )
        self.auth = Authenticator(config, "metaname")

    def test_txt_record(self):
        self.assertEqual(
            self.auth._txt_record("record_name", "record_content"),
            {
                "name": "record_name",
                "type": "TXT",
                "aux": None,
                "ttl": 60,
                "data": "record_content",
            },
            "generated incorrect TXT record",
        )

    def test_client_creation(self):
        with self.assertRaises(errors.PluginError) as cm:
            client = self.auth._metaname_client()
        self.assertIn(
            "API credentials for a Metaname account must be configured before using this plugin",
            cm.exception.args[0],
            "incorrect exception attempting to use client without credential file",
        )

        self.auth._setup_credentials()
        client = self.auth._metaname_client()

        # check that creds loaded from the test metaname.ini
        self.assertEqual(
            client.auth_params,
            (account_reference, api_key),
            "failed to load credentials for authenticator",
        )

    @mock.patch("certbot_dns_metaname.requests.Session.post", side_effect=mock_api_post)
    def test_perform_success(self, mock_post):
        # test using a domain that is present in the account
        self.auth._setup_credentials()
        self.auth._perform(
            "example.com", "_acme-challenge.test.example.com", "test_validation"
        )
        self.assertEqual(
            self.auth.created_record_reference,
            "record_reference",
            "record reference not stored after record creation",
        )

    @mock.patch("certbot_dns_metaname.requests.Session.post", side_effect=mock_api_post)
    def test_perform_invalid_domain(self, mock_post):
        # test using a domain that doesn't belong to the account
        self.auth._setup_credentials()
        with self.assertRaises(
            Exception, msg="attempted use of invalid domain not caught"
        ) as cm:
            self.auth._perform(
                "example.invalid",
                "_acme-challenge.test.example.invalid",
                "test_validation",
            )
        self.assertIn(
            "Unable to find a Metaname DNS zone for test.example.invalid",
            cm.exception.args[0],
            "incorrect exception attempting use of invalid domain",
        )

    @mock.patch("certbot_dns_metaname.requests.Session.post", side_effect=mock_api_post)
    def test_cleanup(self, mock_post):
        self.auth._setup_credentials()
        self.auth._perform(
            "example.com", "_acme-challenge.test.example.com", "test_validation"
        )
        self.assertEqual(
            self.auth.created_record_reference,
            "record_reference",
            "record reference not stored after record creation",
        )
        self.auth._cleanup(
            "example.com", "_acme-challenge.test.example.com", "test_validation"
        )

    @mock.patch("certbot_dns_metaname.requests.Session.post", side_effect=mock_api_post)
    def test_find_zone(self, mock_post):
        self.auth._setup_credentials()
        # zone that is findable
        self.assertEqual(
            self.auth._metaname_domain_name_for_hostname(
                "_acme-challenge.something.example.com"
            ),
            "example.com",
            "_metaname_domain_name_for_hostname finds wrong zone",
        )

        # zone that is not findable
        with self.assertRaises(
            Exception, msg="Zone not present in account not caught"
        ) as cm:
            self.auth._metaname_domain_name_for_hostname(
                "_acme-challenge.something.example.org"
            ),
        self.assertIn(
            "Unable to find a Metaname DNS zone for something.example.org",
            cm.exception.args[0],
            "API response containing neither result or error did not produce expected exception",
        )


if __name__ == "__main__":
    unittest.main()
