# -*- coding: utf-8 -*-

# Copyright (C) 2015 Avencall
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>

import os
import time
import subprocess
import logging

from consul import Consul
from hamcrest import assert_that, not_
from xivo_test_helpers.asset_launching_test_case import AssetLaunchingTestCase
from docker import Client


logger = logging.getLogger(__name__)

class ConsulModuleIntegrationTests(AssetLaunchingTestCase):

    service = 'ctid'
    assets_root = os.path.join(os.path.dirname(__file__), '..', 'assets')
    asset = 'service_discovery'

    def stop_service(self, service):
        self._run_cmd('docker-compose stop {}'.format(service))
        while True:
            running = self.service_status(service)[0]['State']['Running']
            if not running:
                return
            time.sleep(1)

    def test_that_asterisk_is_registered_and_deregistered(self):
        registered = self._is_asterisk_registered_to_consul()

        assert_that(registered, 'asterisk should be registered on consul')

        self.stop_service('asterisk')

        registered = self._is_asterisk_registered_to_consul()

        assert_that(not_(registered), 'asterisk should not be registered on consul')

    def test_that_asterisk_has_maintenance_mode(self):
        maintenance = self._set_asterisk_in_maintenance_mode()

        registred = self._is_asterisk_is_maintenance_mode_in_consul()

    def _is_asterisk_registered_to_consul(self):
        consul = Consul('localhost', '8500', 'the_one_ring')

        status = self.service_status('asterisk')
        ip_address = status[0]['NetworkSettings']['IPAddress']

        start = time.time()
        while time.time() - start < 10:
            services = consul.agent.services()
            for index, service in services.iteritems():
                if service['Service'] == 'asterisk' and service['Address'] == ip_address:
                    return True
            time.sleep(1)

        return False

    def _is_asterisk_is_maintenance_mode_in_consul(self):
        consul = Consul('localhost', '8500', 'the_one_ring')

        status = self.service_status('asterisk')
        ip_address = status[0]['NetworkSettings']['IPAddress']

        services = consul.health.state('passing')
        print services
        services = consul.health.state('critical')
        print services
        return services

    def _set_asterisk_in_maintenance_mode(self):
        asterisk_cmd = "/usr/sbin/asterisk -rx 'discovery set maintenance on'"
        service_id = self.service_status('asterisk')[0]['Id']
        maintenance = self._run_cmd_cli(service_id, asterisk_cmd)
        print maintenance
        return maintenance

    def _unset_asterisk_in_maintenance_mode(self):
        return False


    @staticmethod
    def _run_cmd_cli(container, cmd):
        c = Client(base_url='unix://var/run/docker.sock')
        id = c.exec_create(container, cmd)
        exec_id = c.exec_inspect(id)
        out = c.exec_start(exec_id, stream=False)
        return out