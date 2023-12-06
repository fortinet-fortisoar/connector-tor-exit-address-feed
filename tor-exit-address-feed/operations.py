""" Copyright start
  Copyright (C) 2008 - 2023 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

from requests import request, exceptions as req_exceptions
from connectors.core.connector import get_logger, ConnectorError


logger = get_logger("tor-exit-address-feed")


class TorExitAddressFeed:
    def __init__(self, config, *args, **kwargs):
        server_url = config.get("server_url")
        if not server_url.startswith('https://') and not server_url.startswith('http://'):
            server_url = "https://" + server_url
        self.url = server_url
        self.verify_ssl = config.get("verify_ssl")

    def api_request(self, method, endpoint):
        try:
            endpoint = self.url + endpoint
            response = request(method, endpoint, verify=self.verify_ssl)

            if response.status_code in [200, 201, 204]:
                return response.text
            else:
                if response.text != "":
                    err_resp = response.text
                    error_msg = 'Response [{0}:{1}]'.format(response.status_code, err_resp)
                else:
                    error_msg = 'Response [{0}:{1}]'.format(response.status_code, response.content)
                logger.error(error_msg)
                raise ConnectorError(error_msg)
        except req_exceptions.SSLError:
            logger.error('An SSL error occurred')
            raise ConnectorError('An SSL error occurred')
        except req_exceptions.ConnectionError:
            logger.error('A connection error occurred')
            raise ConnectorError('A connection error occurred')
        except req_exceptions.Timeout:
            logger.error('The request timed out')
            raise ConnectorError('The request timed out')
        except req_exceptions.RequestException:
            logger.error('There was an error while handling the request')
            raise ConnectorError('There was an error while handling the request')
        except Exception as err:
            raise ConnectorError(str(err))


def get_indicators(config, params):
    ob = TorExitAddressFeed(config)
    res = ob.api_request("GET", "")
    data = res.split("\n")[0:-1]  # ignoring last line as it is a blank space
    return data


def check_health_ex(config):
    get_indicators(config, {})
    return True


operations = {
    "get_indicators": get_indicators,
}
