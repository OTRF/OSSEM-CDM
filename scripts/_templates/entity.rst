{{entidad['name']}}
==================

.. list-table::
    :header-rows: 1

    * - name
      - type
      - description
      - sample_value

    {% for a in entidad['attributes'] | sort(attribute='name') %}
    * - {{a['name']}}
      - {{a['type']}}
      - {{a['description']}}
      - {{a['sample_value']}}
    {% endfor %}