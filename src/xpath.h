#ifndef _XPATH_H_
#define _XPATH_H_

int xpath_get_tail_node(const char *xpath, char **node);
int xpath_get_node_key_value(char *xpath, const char *node_name, const char *key_name, char **key_value);
int xpath_get_tail_list_node(const char *xpath, char **node);

#endif //_XPATH_H_