import urllib.parse
from xml.etree.ElementTree import Element, SubElement, tostring

import upnpy.utils as utils


def send(service, action, **action_arguments):

    """
    Example of a RAW SOAP request

    ----------------------------------------------------------------------------
    POST path control URL HTTP/1.0
    HOST: hostname:portNumber
    CONTENT-LENGTH: bytes in body
    CONTENT-TYPE: text/xml; charset="utf-8"
    USER-AGENT: OS/version UPnP/1.1 product/version
    SOAPACTION: "urn:schemas-upnp-org:service:serviceType:v#actionName"

    <?xml version="1.0"?>
    <s:Envelope
    xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"
    s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
        <s:Body>
            <u:actionName xmlns:u="urn:schemas-upnp-org:service:serviceType:v">
                <argumentName>in arg value</argumentName>
                <!-- other in args and their values go here, if any -->
            </u:actionName>
        </s:Body>
    </s:Envelope>
    ----------------------------------------------------------------------------

    :param service: DeviceService object
    :param action: SOAPAction object
    :return: Request response data
    """

    xml_root = Element('s:Envelope')
    xml_root.set('xmlns:s', 'http://schemas.xmlsoap.org/soap/envelope/')
    xml_root.set('s:encodingStyle', 'http://schemas.xmlsoap.org/soap/encoding/')

    xml_body = SubElement(xml_root, 's:Body')

    xml_action_name = SubElement(xml_body, f'u:{action.name}')
    xml_action_name.set('xmlns:u', service.service)

    for argument in action.arguments:
        try:
            argument_value = action_arguments[argument.name]
        except KeyError:
            continue

        xml_action_name_argument = SubElement(xml_action_name, argument.name)
        xml_action_name_argument.text = argument_value

    soap_body = tostring(xml_root, short_empty_elements=False)

    headers = {
        'Host': f'{urllib.parse.urlparse(service.base_url).netloc}',
        'Content-Length': len(soap_body),
        'Content-Type': 'text/xml; charset="utf-8"',
        'SOAPAction': f'"{service.service}#{action.name}"'
    }

    full_control_url = service.base_url + service.control_url
    return utils.make_http_request(full_control_url, data=soap_body, headers=headers)
