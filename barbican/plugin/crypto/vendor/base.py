# Copyright (c) 2026 SAP SE
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import abc


class VendorValidator(abc.ABC):
    """Per-vendor onboarding checks for ProjectTokenConfig registration."""

    @abc.abstractmethod
    def validate_args(self, args):
        """Reject missing/invalid vendor-specific fields on the CLI args."""

    @abc.abstractmethod
    def validate_keys(self, endpoints, args, library_path=None):
        """Confirm MKEK/HMAC keys exist on the HSM reachable via endpoints."""

    def build_metadata(self, args, endpoints):
        """Return the dict to persist in `vendor_metadata`, or None."""
        return None
