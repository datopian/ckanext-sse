import json
from ckan.plugins import toolkit as tk 

@tk.chained_action
def package_update(up_func, context, data_dict): 
    
    # Convert dict to stringify json
    for resource in data_dict.get('resources', []):
        if resource.get('schema'): 
            if isinstance(resource.get('schema'), list) or \
                isinstance(resource.get('schema'), dict):
                resource['schema'] = json.dumps(resource['schema'])

    result = up_func(context, data_dict)
    return result

