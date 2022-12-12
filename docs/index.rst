.. Images
.. |opcuaclient_1| image:: images/opcuaclient.jpg


North OPC UA Client
===================

The *fledge-north-opcuaclient* is a python based OPC UA Client plugin for Fledge that sends data north to an OPC UA Server.

The plugin may be used within a north *task* or *service*. Both of these are created via the *North* menu item in the Fledge user interface.

  - Select *North* from the left hand menu bar

  - Click on the + icon in the top left

  - Choose *opcuaclient* from the plugin selection list

  - Name your task or service

  - Select if you wish to create a service otherwise by default task

  - Click on *Next*

  - Configure the plugin

  +-----------------+
  | |opcuaclient_1| |
  +-----------------+

      - **OPC UA Server URL**: The url of the OPC UA Server to which data will be sent. The URL should be of the form opc.tcp://...

      - **Map**: A map for asset datapoints/attributes to OPC UA node objects. A map JSON structure in which the outer names are Asset names and the inner names are Datapoint names.

        For example:

        .. code-block:: JSON

            {
                "sensor": {
                    "temperature": {
                        "node": "ns=1;i=1013",
                        "type": "Float"
                    }
                }
            }

        - sensor is an asset name
        - temperature is a datapoint name

      - **Source**: The source of the data to be sent, this may be the *readings* or *statistics* data.

  - Click *Next*

  - Enable your task or service and click *Done*

