tests_i = ['assert (flip_case("Hello") == "hELLO");']
item = {}
item['entry_point'] = 'flip_case'
tests_i = [test for test in tests_i if item['entry_point'] in test and 'assert False' not in test]
print(tests_i)