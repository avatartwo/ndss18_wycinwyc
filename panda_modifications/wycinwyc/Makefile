# Don't forget to add your plugin to config.panda!

# The main rule for your plugin. List all object-file dependencies.

LIBS += -lcapstone
O_FILES=$(PLUGIN_OBJ_DIR)/$(PLUGIN_NAME).o

$(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so: $(O_FILES) \
	$(PLUGIN_OBJ_DIR)/segment_tracking.o \
	$(PLUGIN_OBJ_DIR)/callstack_tracking.o \
	$(PLUGIN_OBJ_DIR)/callframe_tracking.o \
	$(PLUGIN_OBJ_DIR)/heapobject_tracking.o \
	$(PLUGIN_OBJ_DIR)/stackobject_tracking.o \
	$(PLUGIN_OBJ_DIR)/printf_tracking.o 
