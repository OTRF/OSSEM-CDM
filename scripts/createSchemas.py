#!/usr/bin/env python3

# Project: OSSEM Common Data Model
# Author: Roberto Rodriguez (@Cyb3rWard0g)
# License: GPLv3
# Reference:

import yaml
import glob
from os import path
from jinja2 import Template
import copy

# ***********************************************
# ******** Processing OSSEM CDM Entities ********
# ***********************************************

print("[+] Processing entity files inside {} directory".format('../schemas/_source/entities'))
# Open OSSEM CDM entity YML file
print("[+] Opening entity YML files..")
entity_files = glob.glob(path.join(path.dirname(__file__), '../schemas/_source/entities', "*.yml"))
entities_loaded = [yaml.safe_load(open(yf).read()) for yf in entity_files]

# Initializing Entities Objects
all_entities = {}

# Create Initial Entity Files
for entity in entities_loaded:
    print("  [>] Processing {}".format(entity['name']))
    # Entity Template
    entity_object = {
        "title": "{}".format(entity['title']),
        "name": "{}".format(entity['name']),
        "type": "{}".format(entity['type']),
        "extends_entities": entity['extends_entities'],
        "description": "{}".format(entity['description']),
        "attributes": []
    }
    # Process Entity Extensions
    entity_names = [entity['name']]
    if entity['extensions']:
        for exa in entity['extensions']:
            if exa['affix'] == 'prefix':
                for name in exa['names']:
                    entity_names.append(name + '_' + entity['name'])
            if exa['affix'] == 'suffix':
                for name in exa['names']:
                    entity_names.append(entity['name'] + '_' + name)
    # Process Entity Attributes
    for en in entity_names:
        for attribute in entity['attributes']:
            attribute_object = {
                "name": en + '_' + attribute['name'],
                "type": attribute['type'],
                "description": attribute['description'],
                "sample_value": attribute['sample_value']
            }
            entity_object['attributes'].append(attribute_object)
    all_entities[entity['name']] = entity_object

# Update Initial Entity Files
def process_exatt(attName, extAttributes):
    updatedAttributes = []
    for extatt in extAttributes:
        updatedAttributes.append({
            "name": (attName + '_' + extatt['name']),
            "type": extatt['type'],
            "description": extatt['description'],
            "sample_value": extatt['sample_value']
            }
        )
    return updatedAttributes
print("[+] Updating Entities..")
for k,v in all_entities.items():
    if v['type'] == 'SubEntity':
        print("  [>] Entity {} extends other entities..".format(v['name']))
        for ee in v['extends_entities']:
            print("    [>] Extending {}..".format(ee['name']))
            extended_attributes = []
            if 'attributes' in ee.keys():
                for eea in ee['attributes']:
                    extended_attributes.extend(process_exatt(eea, v['attributes']))
            else:
                extended_attributes.extend(process_exatt(ee['name'], v['attributes']))
            all_entities[ee['name']]['attributes'].extend(extended_attributes)

# Entity Jinja Template
entity_template = Template(open('_templates/entity.rst').read())

# Build Entity Files
for k,v in all_entities.items():
    # Build Default Entity Files
    with open(r'../schemas/entities/{}.yml'.format(v['name']), 'w') as file:
        yaml.dump(v, file, sort_keys=False)

    # ******** Process Entities for DOCS ********
    entity_for_render = copy.deepcopy(v)
    entity_rst = entity_template.render(entidad=entity_for_render)
    open('../docs/source/entities/{}.rst'.format(v['name']), 'w').write(entity_rst)

# ***********************************************
# ********* Processing OSSEM CDM Tables *********
# ***********************************************

print("[+] Processing table files inside {} directory".format('../schemas/_source/tables'))
# Open OSSEM CDM Table YML file
print("[+] Opening table YML files..")
#table_files = glob.glob(path.join(path.dirname(__file__), '../schemas/_source/tables', "*.yml"))
#tables_loaded = [yaml.safe_load(open(yf).read()) for yf in table_files]

# Loop Through Table Files
#for table in tables_loaded:
#    print("  [>] Processing {} Table.".format(table['name']))
    # Table Template
#    table_template = {
#        "title": "{}".format(table['title']),
#        "name": "{}".format(table['name']),
#        "description": "{}".format(table['description']),
#        "attributes": []
#    }
    # Process Table Attributes
#    for ta in table['attributes']:
#        entity_load = all_entities[ta]
        #entity_load = yaml.safe_load(open('../schemas/entities/{}.yml'.format(ta)).read())
        #[el.update({"entity": ta}) for el in entity_load['attributes']]
        #table_template['attributes'].extend(entity_load['attributes'])
#        table_template['attributes'].extend(all_entities[ta]['attributes'])
    # Build Table File
#    with open(r'../schemas/tables/{}.yml'.format(table['name']), 'w') as file:
 #       yaml.dump(table_template, file, sort_keys=False)


# ******** Process Entities for Azure Sentinel ********
    # snake_case -> CamelCase
    #for oa in v['attributes']:
    #    components = oa['name'].split('_')
    #    oa['name'] = components[0].title() + ''.join(x.title() for x in components[1:])
    # Build AZ Sentinel Entity Files
    #with open(r'../contrib/az-sentinel/entities/{}.yml'.format(v['name']), 'w') as file:
     #   yaml.dump(v, file, sort_keys=False)
