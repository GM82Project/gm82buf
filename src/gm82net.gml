#define __gm82net_init
    globalvar __gm82net_version;
    __gm82net_version=131
    
    show_debug_message("The Network extension is DEPRECATED. Please update your project to use the Buffer extension.")
    
    obj=object_add()
    object_event_add(obj,ev_create,0,"
        globalvar gm82buf_version;
        if (gm82buf_version) show_error(
            'The Buffer extension cannot be combined with the Network extension. Please remove the Network extension as it is old and no longer supported.'
        ,true)
        instance_destroy()
    ")
    room_instance_add(room_first,0,0,obj)
//
//