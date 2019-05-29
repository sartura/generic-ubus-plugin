#ifndef _XPATH_H_
#define _XPATH_H_

int xpath_get_tail_node(const char *xpath, char **node);
int xpath_get_last_list_attribute_name(const char *xpath, char **attribute_name);
int xpath_get_list_node(const char *xpath, char **node);

#endif //_XPATH_H_