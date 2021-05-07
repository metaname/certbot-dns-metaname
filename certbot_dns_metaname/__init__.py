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

"""
Certbot plugin for DNS authentication using the Metaname DNS API.

Metaname <support@metaname.nz> 2021-05-06
"""

import json

import requests
import zope.interface

from certbot import errors
from certbot import interfaces
from certbot.plugins import dns_common

## Metaname API client


class MetanameApiClient:
    """
    Make requests to the Metaname JSON-RPC API, documented at <https://metaname.net/api/1.1/doc>.
    """

    default_api_endpoint = "https://metaname.net/api/1.1"
    minimum_ttl = 60  # Specified by Metaname

    def __init__(self, account_reference, api_key, endpoint=None):
        if endpoint is None:
            self.endpoint = MetanameApiClient.default_api_endpoint
        else:
            self.endpoint = endpoint
        self.request_id = 0
        self.session = requests.Session()
        self.session.headers.update({"content-type": "application/json"})

        # default JSON skeleton required for all requests
        self.payload = {"jsonrpc": "2.0"}
        # auth parameters prepend to every request
        self.auth_params = (account_reference, api_key)

    def request(self, method, *params):
        """
        Makes a request to the API. Returns decoded "result" if the request succeeds, otherwises raises an exception.
        """

        payload = {**self.payload, "id": self.request_id, "method": method}
        if params is not None:
            payload["params"] = (*self.auth_params, *params)

        try:
            response = self.session.post(self.endpoint, json=payload).json()
        except json.decoder.JSONDecodeError as e:
            raise Exception(f"Metaname API didn't return a JSON response: {e}") from e
        except Exception as e:
            raise Exception(f"Metaname API call failed: {e}") from e

        if response.get("id", None) != self.request_id:
            raise Exception(
                f"Metaname API returned out of sequence response: {response}"
            )
        else:
            self.request_id += 1

        if "result" in response:
            return response["result"]
        elif "error" in response:
            raise Exception(f"Metaname API error: {response['error']}")
        else:
            raise Exception(f"Metaname API returned an invalid response: {response}")


## Certbot plugin implementation


@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """
    Certbot DNS authenticator using the Metaname DNS API
    """

    description = __doc__

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.auth = None
        self.metaname_client = None
        self.created_record_reference = None

    def more_info(self):
        return self.__doc__

    @classmethod
    def add_parser_arguments(cls, add):
        super().add_parser_arguments(
            add, default_propagation_seconds=10
        )  # Metaname DNS updates should be synchronous so this "propagation seconds" value could be lowered
        add("credentials", help="INI file where Metaname API credentials are stored.")
        add(
            "endpoint",
            help="HTTPS URL for the Metaname API endpoint",
            default=MetanameApiClient.default_api_endpoint,
        )

    def _setup_credentials(self):
        self.auth = self._configure_credentials(
            "credentials",
            "INI file where Metaname API credentials are stored",
            {
                "account_reference": "a four character Metaname account reference",
                "api_key": "a Metaname API key",
            },
        )

    def _txt_record(self, name, content):
        """
        Returns a dictionary containing a TXT record in the format required for the Metaname API.
        """

        return {
            "name": name,
            "type": "TXT",
            "aux": None,
            "ttl": MetanameApiClient.minimum_ttl,
            "data": content,
        }

    def _metaname_client(self):
        if self.auth is None:
            raise errors.PluginError(
                "API credentials for a Metaname account must be configured before using this plugin."
            )
        if self.metaname_client is None:
            self.metaname_client = MetanameApiClient(
                self.auth.conf("account_reference"),
                self.auth.conf("api_key"),
                endpoint=self.conf("endpoint"),
            )
        return self.metaname_client

    def _metaname_domain_name_for_hostname(self, hostname):
        """
        For a given hostname attempt to find the parent zone it belongs to.

        For instance, if "example.com" is hosted with Metaname then "example.com" will be returned for the hostname "test.example.com".
        If there are no candidate domain names then an exception is raised.
        """

        # XXX At the moment this hits some bugs in the Metaname API (the validation on "domain_name" is incorrect, there is no method to return a list of hosted zones so it uses trial and error)
        hostname = hostname.strip(".").split(".", 1)[
            1:
        ]  # remove the well-known prefix from the validation hostname
        guesses = dns_common.base_domain_name_guesses(hostname)
        for guess in guesses:
            try:
                self._metaname_client().request("dns_zone", guess)
            except Exception:
                continue
            else:
                return guess
        raise errors.PluginError(f"Unable to find any Metaname zone for {hostname}")

    def _perform(self, domain, validation_name, validation):
        """
        Creates the TXT record in domain for the given validation hostname and validation string.
        """

        domain_name = self._metaname_domain_name_for_hostname(validation_name)
        try:
            response = self._metaname_client().request(
                "create_dns_record",
                domain_name,
                self._txt_record(f"{validation_name}.", validation),
            )
        except Exception as e:
            raise errors.PluginError(
                f"Unable to create an acme-challenge record in the zone {domain}: {e}"
            ) from e
        else:
            self.created_record_reference = response

    def _cleanup(self, domain, validation_name, validation):
        """
        Removes the TXT record created by _perform. This must be called after _perform so that the record ID to be deleted is known.
        """

        if self.created_record_reference is None:
            raise errors.PluginError(
                "Cannot clean up DNS because the record hasn't been created yet"
            )

        domain_name = self._metaname_domain_name_for_hostname(validation_name)
        try:
            self._metaname_client().request(
                "delete_dns_record", domain_name, self.created_record_reference
            )
        except Exception as e:
            raise errors.PluginError(
                f"Unable to delete the acme-challenge record in the zone {domain}: {e}"
            ) from e
        else:
            self.created_record_reference = None
