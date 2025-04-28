from pyeudiw.duckle_ql.attribute_mapper import AttributeMapper

def test_apply_mappings_with_single_match():
    mappings = [{'credentials[0].name': 'full_name'}]
    data = [{'name': 'Alice'}]
    mapper = AttributeMapper(mappings)
    result = mapper.apply_mappings(data)
    assert result == {'full_name': 'Alice'}


def test_apply_mappings_with_nested_match():
    mappings = [{'credentials[0].details.age': 'user_age'}]
    data = [{'details': {'age': 30}}]
    mapper = AttributeMapper(mappings)
    result = mapper.apply_mappings(data)
    assert result == {'user_age': 30}


def test_apply_mappings_with_wildcard_match():
    mappings = [{'credentials[*].value': 'all_values'}]
    data = [{'value': 10}, {'value': 20}, {'value': 30}]
    mapper = AttributeMapper(mappings)
    result = mapper.apply_mappings(data)
    assert result == {'all_values': [10, 20, 30]}


def test_apply_mappings_with_wildcard_nested_match():
    mappings = [{'credentials[*].info.city': 'all_cities'}]
    data = [{'info': {'city': 'Rome'}}, {'info': {'city': 'Milan'}}]
    mapper = AttributeMapper(mappings)
    result = mapper.apply_mappings(data)
    assert result == {'all_cities': ['Rome', 'Milan']}


def test_apply_mappings_with_multiple_mappings():
    mappings = [
        {'credentials[0].name': 'full_name'},
        {'credentials[0].details.age': 'user_age'}
    ]
    data = [{'name': 'Bob', 'details': {'age': 25}}]
    mapper = AttributeMapper(mappings)
    result = mapper.apply_mappings(data)
    assert result == {'full_name': 'Bob', 'user_age': 25}


def test_apply_mappings_with_no_match():
    mappings = [{'non_existent_path': 'output_field'}]
    data = [{'some_data': 'value'}]
    mapper = AttributeMapper(mappings)
    result = mapper.apply_mappings(data)
    assert result == {}


def test_apply_mappings_with_wildcard_and_specific_index():
    mappings = [{'credentials[*].value': 'all_values'}, {'credentials[1].value': 'second_value'}]
    data = [{'value': 10}, {'value': 20}, {'value': 30}]
    mapper = AttributeMapper(mappings)
    result = mapper.apply_mappings(data)
    assert result == {'all_values': [10, 20, 30], 'second_value': 20}

def test_apply_mappings_with_nested_list():
    mappings = [{'credentials[0].items[*].name': 'all_item_names'}]
    data = [{'items': [{'name': 'Item 1'}, {'name': 'Item 2'}]}]
    mapper = AttributeMapper(mappings)
    result = mapper.apply_mappings(data)
    assert result == {'all_item_names': ['Item 1', 'Item 2']}