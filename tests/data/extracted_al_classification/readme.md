# Test Assemblyline definition

The assemblyline definition in the folder was acquired from a running assemblyline instance in Azul.
This was done using this script:

```python
import json
import logging

from azul_plugin_assemblyline import common
from azul_plugin_assemblyline.settings import Settings as alSettings

# Function copied from tests.support.py

resetEnv()
local_settings = alSettings(
    al_url="https://assemblyline",
    al_user="<user-name>",
    al_token="<user-token>",
)
al_client = common.setup_al_client(local_settings, logging.Logger("COMMMON"))
print(json.dumps(al_client.get_classification_engine().original_definition))
```

This was then modified to make it more useful for testing.
