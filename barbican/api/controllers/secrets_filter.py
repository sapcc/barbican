# Copyright 2012 OpenStack Foundation
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

from oslo_log import log as logging

from barbican.common import validators
from barbican.api import controllers
from barbican.model import repositories as repo
from barbican.common import exception
from barbican.common import utils
from barbican import i18n as u
import pecan

LOG = logging.getLogger(__name__)

def _secret_not_found():
    """Throw exception indicating secret not found."""
    pecan.abort(404, u._('Secret not found.'))


def _invalid_secret_id():
    """Throw exception indicating secret id is invalid."""
    pecan.abort(404, u._('Not Found. Provided secret id is invalid.'))

class SecretsFilter(controllers.ACLMixin):
    
    def __init__(self, secret):
        self.secret = secret
        self.validator = validators.NewSecretValidator()
        self.secret_repo = repo.get_secret_repository()

    def update(self, req, secret_id, tag_value):
        secret_repo = repo.get_secret_repository(req.context)
        try:
            secret = secret_repo.get(secret_id)
            secret.tags.add(tag_value)
            secret_repo.save(secret)
        except exception.NotFound:
            _secret_not_found()
        except exception.Invalid:
            _invalid_secret_id()

    @pecan.expose()
    def _lookup(self, secret_id, *remainder):
        if not utils.validate_id_is_uuid(secret_id):
            _invalid_secret_id()()
        secret = self.secret_repo.get_secret_by_id(
            entity_id=secret_id, suppress_exception=True)
        if not secret:
            _secret_not_found()

        return SecretsFilter(secret), remainder

    def delete(self, req, secret_id, tag_value):
        secret_repo = repo.get_secret_repository(req.context)
        try:
            secret = secret_repo.get(secret_id)
            if tag_value not in secret.tags:
                _secret_not_found()
            secret.tags.remove(tag_value)
            secret_repo.save(secret)
        except exception.NotFound:
            _secret_not_found()
        except exception.Invalid:
            _invalid_secret_id()
