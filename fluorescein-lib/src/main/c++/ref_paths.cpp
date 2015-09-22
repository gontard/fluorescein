#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <jni.h>
#include "jvmti.h"

/* ------------------------------------------------------------------- */
/* Some constant maximum sizes */

#define MAX_TOKEN_LENGTH        16
#define MAX_CLASS_NAME_LENGTH  1024

static jvmtiEnv *jvmti = NULL;
static jvmtiCapabilities capa;

/* Global agent data structure */

typedef struct {
    /* JVMTI Environment */
    jvmtiEnv      *jvmti;
    jboolean       vm_is_started;

    /* Data access Lock */
    jrawMonitorID  lock;
	
	/* Options */
    char* classname;
    int   max_count;	
	
    jboolean dumpInProgress;

	JavaVM*  jvm;
	jclass	 klass;
	jlong	 klassTag;

} GlobalAgentData;

static GlobalAgentData *gdata;

typedef struct Referrer {
	jlong tag;
	jlong refereeTag;
	Referrer* next;
} Referrer;


struct ObjectInfo {
	jobject obj;	
	jvmtiObjectReferenceKind kind;
	jlong size;
	jstring jstr;
	char* classname;
	int visited;
	Referrer* referrers;
};

typedef struct ObjectInfoList {
	ObjectInfo* obj;
	struct ObjectInfoList* next;
} ObjectInfoList;

ObjectInfoList* objList = NULL;

typedef struct RefPaths {
	ObjectInfo* path;
	struct RefPaths* next;
} RefPaths;

static RefPaths* ref_paths;


/* Every JVMTI interface returns an error code, which should be checked
 *   to avoid any cascading errors down the line.
 *   The interface GetErrorName() returns the actual enumeration constant
 *   name, making the error messages much easier to understand.
 */
static void
check_jvmti_error(jvmtiEnv *jvmti, jvmtiError errnum, const char *str)
{
    if ( errnum != JVMTI_ERROR_NONE ) {
        char       *errnum_str;

        errnum_str = NULL;
        (void)jvmti->GetErrorName(errnum, &errnum_str);

        printf("ERROR: JVMTI: %d(%s): %s\n", errnum, (errnum_str==NULL?"Unknown":errnum_str), (str==NULL?"":str));
    }
}


/* Enter a critical section by doing a JVMTI Raw Monitor Enter */
static void
enter_critical_section(jvmtiEnv *jvmti)
{
    jvmtiError error;

    error = jvmti->RawMonitorEnter(gdata->lock);
    check_jvmti_error(jvmti,error, "Cannot enter with raw monitor");
}

/* Exit a critical section by doing a JVMTI Raw Monitor Exit */
static void
exit_critical_section(jvmtiEnv *jvmti)
{
    jvmtiError error;

    error = jvmti->RawMonitorExit(gdata->lock);
    check_jvmti_error(jvmti, error, "Cannot exit with raw monitor");
}

void describe(jvmtiError err) {
      jvmtiError err0;
      char *descr;
      err0 = jvmti->GetErrorName(err, &descr);
      if (err0 == JVMTI_ERROR_NONE) {
          printf(descr);
      } else {
          printf("error [%d]", err);
      }
 }


//-------------------------------------------------------------
static jvmtiIterationControl JNICALL
heap_root_callback(jvmtiHeapRootKind  root_kind,
                jlong class_tag, jlong size, jlong* tag_ptr,
                void *user_data)
{
	return JVMTI_ITERATION_CONTINUE;

}

static jvmtiIterationControl JNICALL
stack_ref_callback(jvmtiHeapRootKind  root_kind,
                jlong class_tag, jlong size, jlong* tag_ptr,
                jlong thread_tag, jint depth, 
                jmethodID method, 
                jint slot, void *user_data)
{
	return JVMTI_ITERATION_CONTINUE;
}

void DeallocateObject(ObjectInfo* obj) {
	JNIEnv* env;
	(gdata->jvm)->GetEnv((void**)&env, JNI_VERSION_1_2);

	if (obj) {
		Referrer* referrer = obj->referrers;
		while (referrer) {
			Referrer* ref = referrer;
			referrer = referrer->next;
			delete(ref);
		}
		delete(obj);		
	}
}

void AddToPathsList(ObjectInfo* obj_info) {
	RefPaths* list = ref_paths;

	if (list == NULL) {
		ref_paths = new RefPaths();
		ref_paths->path = obj_info;
		ref_paths->next = NULL;
	} 
	else {
		while (list->next != NULL) {
			list = list->next;
		}
		RefPaths* ref_path =  new RefPaths();
		ref_path->path = obj_info;
		ref_path->next = NULL;

		list->next = ref_path;		
	}
}

static jvmtiIterationControl JNICALL
object_ref_clean_callback(jvmtiObjectReferenceKind reference_kind,
					jlong class_tag, jlong size, jlong* tag_ptr,
					jlong referrer_tag, jint referrer_index, void *user_data)
{
	*tag_ptr = 0;

	return JVMTI_ITERATION_CONTINUE;

}

static jvmtiIterationControl JNICALL
object_ref_callback(jvmtiObjectReferenceKind reference_kind,
					jlong class_tag, jlong size, jlong* tag_ptr,
					jlong referrer_tag, jint referrer_index, void *user_data)
{

	ObjectInfo* obj_info = NULL;
	// if this object's tag is set
	if (*tag_ptr != NULL) { 
		if (gdata->klassTag == 1) {
			if (*tag_ptr == gdata->klassTag) {
				obj_info = new ObjectInfo();
				memset(obj_info, 0 , sizeof(ObjectInfo));
				obj_info->size = size;
				obj_info->visited = 1;
				obj_info->kind = reference_kind;

				*tag_ptr = (jlong)(ptrdiff_t)(void*)obj_info;
				gdata->klassTag = *tag_ptr;
			}
		} else {
			obj_info = (ObjectInfo*)*tag_ptr;
			if (obj_info->visited == 1)
				return JVMTI_ITERATION_CONTINUE;
		}
	}
	// if tag is not present, then create ObjectInfo and set it as it's tag.
	else {

		obj_info = new ObjectInfo();
		memset(obj_info, 0 , sizeof(ObjectInfo));
		obj_info->size = size;
		obj_info->visited = 1;
		obj_info->kind = reference_kind;

		*tag_ptr = (jlong)(ptrdiff_t)(void*)obj_info;

		//Add the new ObjectInfo to ObjectInfo's list
		if (objList == NULL) {
			objList = new ObjectInfoList();
			objList->obj = obj_info;
			objList->next = NULL;
		} else {
			ObjectInfoList* list = objList;
			while (list->next != NULL) {
				list = list->next;
			}
			ObjectInfoList* objinfo = new ObjectInfoList();
			objinfo->obj = obj_info;
			objinfo->next = NULL;

			list->next = objinfo;
		}	

	}
	
/*	if (referrer_tag != NULL) {
		if (obj_info->referrers == NULL) {
			obj_info->referrers = new Referrer();
			obj_info->referrers->tag = referrer_tag;
			obj_info->referrers->refereeTag = *tag_ptr;
			obj_info->referrers->next = NULL;
		} else {
			Referrer* referrer = obj_info->referrers;
			while (referrer->next != NULL) {
				referrer = referrer->next;
			}
			Referrer* ref = new Referrer();
			ref->tag = referrer_tag;
			ref->refereeTag = *tag_ptr;
			ref->next = NULL;

			referrer->next = ref;			
		}
	} 

	if (class_tag == gdata->klassTag) {
			AddToPathsList(obj_info);
	}*/

	return JVMTI_ITERATION_CONTINUE;
}

static jvmtiIterationControl JNICALL
heap_object_callback(jlong class_tag, jlong size, jlong* tag_ptr,
                       void *user_data)
{
	static jlong i = 1;

	ObjectInfo* obj_info = new ObjectInfo();
	memset(obj_info, 0 , sizeof(ObjectInfo));
	obj_info->size = size;
//	obj_info->kind = reference_kind;

	//Add the new ObjectInfo to ObjectInfo's list
	if (objList == NULL) {
		objList = new ObjectInfoList();
		objList->obj = obj_info;
		objList->next = NULL;
	} else {
		ObjectInfoList* list = objList;
		while (list->next != NULL) {
			list = list->next;
		}
		ObjectInfoList* objinfo = new ObjectInfoList();
		objinfo->obj = obj_info;
		objinfo->next = NULL;

		list->next = objinfo;
	}	

	AddToPathsList(obj_info);

	*tag_ptr = (jlong)(ptrdiff_t)(void*)obj_info;

	return JVMTI_ITERATION_CONTINUE;
}

void visit(ObjectInfo* object) {
	jvmtiError    err;
	jint count = 0;
	jobject* obj;
	jlong* tag_result_ptr = new jlong;
	JNIEnv* env;

	jlong tag = (jlong)(ptrdiff_t)object;

	err = gdata->jvmti->GetObjectsWithTags(1, (jlong*)&tag, &count, &obj, &tag_result_ptr);
	if (obj != NULL) {
		//object->obj = *obj;

		(gdata->jvm)->GetEnv((void**)&env, JNI_VERSION_1_2);
		jmethodID mid =  env->GetMethodID(gdata->klass, "toString", "()Ljava/lang/String;");

		jstring jstr = (jstring)env->CallObjectMethod(*obj, mid);
		//object->jstr = jstr;
		char* str = (char*)env->GetStringUTFChars(jstr, NULL);
		//object->classname = str;

		printf("\n- ");
		switch(object->kind) {
		case JVMTI_REFERENCE_CONSTANT_POOL: 
			printf("Constant Pool Entry: ");
			break;
		case JVMTI_REFERENCE_STATIC_FIELD:
			printf("Class Static Field: ");
			break;
		case JVMTI_REFERENCE_INTERFACE:
			printf("Interface: ");
			break;
		case JVMTI_REFERENCE_CLASS_LOADER:
			printf("ClassLoader: ");
			break;
		case JVMTI_REFERENCE_ARRAY_ELEMENT:
			printf("Array Element: ");
			break;
		case JVMTI_REFERENCE_FIELD:
			printf("Instance Field: ");
			break;
		default:
			break;
		}

		printf("%s", str);

		env->DeleteLocalRef(*obj);
		env->DeleteLocalRef(jstr);

		if (jstr) {
			env->ReleaseStringUTFChars(jstr, str);
		}


	}
}

ObjectInfoList* parentList;

void dfsPrintRefPaths(ObjectInfo* object) {

	visit(object);	

	// addto(parentlist, object);
	if (parentList == NULL) {
		parentList = new ObjectInfoList();
		parentList->obj = object;
		parentList->next = NULL;
	} else {
		ObjectInfoList* list = parentList;
		while (list->next != NULL) {
			list = list->next;
		}
		ObjectInfoList* objinfo = new ObjectInfoList();
		objinfo->obj = object;
		objinfo->next = NULL;

		list->next = objinfo;
	}	

	Referrer* referrer = object->referrers;

	while (referrer) {
		ObjectInfo* obj = (ObjectInfo*)referrer->tag;
		//Check if obj is unvisited
		dfsPrintRefPaths(obj);
		referrer = referrer->next;				

		if (referrer) {
			printf("\n\n Another path..");

			//print(parentlist)
			ObjectInfoList* list = parentList;
			while (list != NULL) {
				visit(list->obj);
				list = list->next;
			}			
		}
	}

	// deletelastobject(parentlist);
	ObjectInfoList* list = parentList;
	ObjectInfoList* prevNode = NULL;
	while (list->next != NULL) {
		prevNode = list;
		list = list->next;
	}
	if(prevNode == NULL) {
		delete(parentList);
		parentList = NULL;
	} else {
		prevNode->next = NULL;
	}

}

static void JNICALL
dataDumpRequest(jvmtiEnv *jvmti)
{
    enter_critical_section(jvmti); {
    printf("%s\n", gdata->classname);
	if ( !gdata->dumpInProgress ) {
	    gdata->dumpInProgress = JNI_TRUE;

        gdata->klassTag = 1;
		gdata->jvmti->SetTag(gdata->klass, gdata->klassTag);

		jint count = 0;
		void* user_data = NULL;

        jvmti->IterateOverReachableObjects(&heap_root_callback, &stack_ref_callback, &object_ref_callback, user_data);

		// print ref paths
		RefPaths* list = ref_paths;
		int max = gdata->max_count;

		printf("Reference paths of instances of %s ....\n", gdata->classname);
		while ((list != NULL) && (max >= 0) ) {
			ObjectInfo* object = (ObjectInfo*)list->path;
			printf("\n\nReference Path:");
			dfsPrintRefPaths(object);
			list = list->next;
			max--;
			
		}

		//unset tags
        jvmti->IterateOverReachableObjects(&heap_root_callback, &stack_ref_callback, &object_ref_clean_callback, user_data);

		//delete object info list
		ObjectInfoList* list1 = objList;
		while (list1) {
			ObjectInfoList* node = list1;
			list1 = list1->next;
			DeallocateObject(node->obj);
			delete(node);
		}
		objList = NULL;
		
		//delete ref paths list
		list = ref_paths;
		RefPaths* path;

		while (list != NULL) {
			path = list;
			list = list->next;
			delete(path);			
		}
		ref_paths = NULL;

		gdata->klassTag = 1;
		gdata->dumpInProgress = JNI_FALSE;
	}
	} exit_critical_section(jvmti);	
}


// VM Death callback
static void JNICALL callbackVMDeath(jvmtiEnv *jvmti_env, JNIEnv* jni_env)
{
    jvmtiError          err;
	/// Make sure everything has been garbage collected 
    err = jvmti->ForceGarbageCollection();
    check_jvmti_error(jvmti, err, "Forced garbage collection failed");

	enter_critical_section(jvmti); {
	err = jvmti->SetEventNotificationMode(JVMTI_DISABLE, 
			    JVMTI_EVENT_DATA_DUMP_REQUEST, NULL);
	check_jvmti_error(jvmti, err, "SetEventNotificationMode failure");
	
	
	} exit_critical_section(jvmti);

}

//----------------------------------------------------------------------------

// VM init callback
static void JNICALL callbackVMInit(jvmtiEnv *jvmti_env, JNIEnv* jni_env, jthread thread)
{
	enter_critical_section(jvmti); {
		jvmtiError error;

    error = jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_EXCEPTION, (jthread)NULL);
    check_jvmti_error(jvmti_env, error, "Cannot set event notification");

	jclass cls = jni_env->FindClass(gdata->classname);
	jthrowable exp = jni_env->ExceptionOccurred();
	if (exp) {
		jni_env->ExceptionDescribe();
        jni_env->ExceptionClear();
	}
	if (cls) {
		gdata->klass = (jclass)jni_env->NewGlobalRef(cls);
        gdata->klassTag = 1;

		gdata->jvmti->SetTag(gdata->klass, gdata->klassTag);
	}

    } exit_critical_section(jvmti);

}


/* Get a token from a string (strtok is not MT-safe)
 *    str	String to scan
 *    seps      Separation characters
 *    buf       Place to put results
 *    max       Size of buf
 *  Returns NULL if no token available or can't do the scan.
 */
char *
get_token(char *str, char *seps, char *buf, int max)
{
    int len;
    
    buf[0] = 0;
    if ( str==NULL || str[0]==0 ) {
	return NULL;
    }
    str += strspn(str, seps);
    if ( str[0]==0 ) {
	return NULL;
    }
    len = (int)strcspn(str, seps);
    if ( len >= max ) {
	return NULL;
    }
    (void)strncpy(buf, str, len);
    buf[len] = 0;
    return str+len;
}

/* Send message to stderr or whatever the error output location is and exit  */
void
fatal_error(const char * format, ...)
{
    va_list ap;

    va_start(ap, format);
    (void)vfprintf(stderr, format, ap);
    (void)fflush(stderr);
    va_end(ap);
    exit(3);
}

/* Send message to stdout or whatever the data output location is */
void
stdout_message(const char * format, ...)
{
    va_list ap;

    va_start(ap, format);
    (void)vfprintf(stdout, format, ap);
    va_end(ap);
}

static void
parse_agent_options(char *options)
{
    char token[MAX_TOKEN_LENGTH];
    char *next;

    gdata->max_count = 10; /* Default max=n */
    
    /* Parse options and set flags in gdata */
    if ( options==NULL ) {
	return;
    }
   
    /* Get the first token from the options string. */
    next = get_token(options, ",=", token, sizeof(token));

    /* While not at the end of the options string, process this option. */
    while ( next != NULL ) {
	if ( strcmp(token,"help")==0 ) {
	    stdout_message("The refpaths JVMTI agent\n");
	    stdout_message("\n");
	    stdout_message(" java -agent:refpaths[=options] ...\n");
	    stdout_message("\n");
	    stdout_message("The options are comma separated:\n");
	    stdout_message("\t help\t\t\t Print help information\n");
	    stdout_message("\t max=n\t\t Only list paths of top n instances\n");
	    stdout_message("\t classname=item\t\t Print ref paths of instances of this class\n");
	    stdout_message("\n");
	    stdout_message("item\t Qualified class name\n");
	    stdout_message("\t\t e.g. (java.lang.String)\n");
	    stdout_message("\n");
	    exit(0);
	} else if ( strcmp(token,"max")==0 ) {
            char number[MAX_TOKEN_LENGTH];
	    
	    /* Get the numeric option */
	    next = get_token(next, ",=", number, (int)sizeof(number));
	    /* Check for token scan error */
	    if ( next==NULL ) {
		fatal_error("ERROR: max=n option error\n");
	    }
	    /* Save numeric value */
	    gdata->max_count = atoi(number);
	} else if ( strcmp(token,"classname")==0 ) {
	    int   used;
	    int   maxlen;

	    maxlen = MAX_CLASS_NAME_LENGTH;
	    if ( gdata->classname == NULL ) {
		gdata->classname = (char*)calloc(maxlen+1, 1);
		used = 0;
	    } else {
		used  = (int)strlen(gdata->classname);
		gdata->classname[used++] = ',';
		gdata->classname[used] = 0;
		gdata->classname = (char*)
			     realloc((void*)gdata->classname, used+maxlen+1);
	    }
	    if ( gdata->classname == NULL ) {
		fatal_error("ERROR: Out of malloc memory\n");
	    }
	    /* Add this item to the list */
	    next = get_token(next, ",=", gdata->classname+used, maxlen);
	    /* Check for token scan error */
	    if ( next==NULL ) {
		fatal_error("ERROR: include option error\n");
	    }
	} else if ( token[0]!=0 ) {
	    /* We got a non-empty token and we don't know what it is. */
	    fatal_error("ERROR: Unknown option: %s\n", token);
	}
	/* Get the next token (returns NULL if there are no more) */
        next = get_token(next, ",=", token, sizeof(token));
    }
}

JNIEXPORT jint JNICALL Agent_OnLoad(JavaVM *jvm, char *options, void *reserved)
 {
      static GlobalAgentData data;
      jvmtiError error;
      jint res;
      jvmtiEventCallbacks callbacks;


      /* Setup initial global agent data area
     *   Use of static/extern data should be handled carefully here.
     *   We need to make sure that we are able to cleanup after ourselves
     *     so anything allocated in this library needs to be freed in
     *     the Agent_OnUnload() function.
     */
     (void)memset((void*)&data, 0, sizeof(data));
     gdata = &data;

      /*  We need to first get the jvmtiEnv* or JVMTI environment */

	 gdata->jvm = jvm;

      res = jvm->GetEnv((void **) &jvmti, JVMTI_VERSION_1_0);

      if (res != JNI_OK || jvmti == NULL) {
	/* This means that the VM was unable to obtain this version of the
         *   JVMTI interface, this is a fatal error.
         */
        printf("ERROR: Unable to access JVMTI Version 1 (0x%x),"
                " is your J2SE a 1.5 or newer version?"
                " JNIEnv's GetEnv() returned %d\n",
               JVMTI_VERSION_1, res);

      }

      /* Here we save the jvmtiEnv* for Agent_OnUnload(). */
    gdata->jvmti = jvmti;

    /* Parse any options supplied on java command line */
    parse_agent_options(options);

    (void)memset(&capa, 0, sizeof(jvmtiCapabilities));
    capa.can_signal_thread = 1;
    capa.can_get_owned_monitor_info = 1;
    capa.can_generate_method_entry_events = 1;
    capa.can_generate_exception_events = 1;
    capa.can_generate_vm_object_alloc_events = 1;
    capa.can_tag_objects = 1;	

    error = jvmti->AddCapabilities(&capa);
    check_jvmti_error(jvmti, error, "Unable to get necessary JVMTI capabilities.");


    (void)memset(&callbacks, 0, sizeof(callbacks));
    callbacks.VMInit = &callbackVMInit; /* JVMTI_EVENT_VM_INIT */
    callbacks.VMDeath = &callbackVMDeath; /* JVMTI_EVENT_VM_DEATH */
	callbacks.DataDumpRequest = &dataDumpRequest; 

    error = jvmti->SetEventCallbacks(&callbacks, (jint)sizeof(callbacks));
    check_jvmti_error(jvmti, error, "Cannot set jvmti callbacks");

    /* At first the only initial events we are interested in are VM
     *   initialization, VM death, and Class File Loads.
     *   Once the VM is initialized we will request more events.
    */
    error = jvmti->SetEventNotificationMode(JVMTI_ENABLE,
                          JVMTI_EVENT_VM_INIT, (jthread)NULL);
    error = jvmti->SetEventNotificationMode(JVMTI_ENABLE,
                          JVMTI_EVENT_VM_DEATH, (jthread)NULL);
	error = jvmti->SetEventNotificationMode(JVMTI_ENABLE, 
			    JVMTI_EVENT_DATA_DUMP_REQUEST, NULL);
    error = jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_VM_OBJECT_ALLOC, (jthread)NULL);
    check_jvmti_error(jvmti,error, "Cannot set event notification");


    /* Here we create a raw monitor for our use in this agent to
     *   protect critical sections of code.
     */
    error = jvmti->CreateRawMonitor("agent data", &(gdata->lock));
    check_jvmti_error(jvmti,error, "Cannot create raw monitor");

    /* We return JNI_OK to signify success */
    return JNI_OK;


 }

/* Agent_OnUnload: This is called immediately before the shared library is
 *   unloaded. This is the last code executed.
 */
JNIEXPORT void JNICALL
Agent_OnUnload(JavaVM *vm)
{
	/* Make sure all malloc/calloc/strdup space is freed */


}

/**
 * This is the JNI native function that will be executed for every call to the
 * org.gontard.fluorescein.Fluorescein.nativeNewEvent(Object) method.
 *
 * @param env            the pointer to the JVM environment.
 * @param fluoresceinClass  org.gontard.fluorescein.Fluorescein Java class.
 * @param object the object.
 */
extern "C"
JNIEXPORT void JNICALL Java_org_gontard_fluorescein_Fluorescein_printPathToRoot(JNIEnv *env, jclass fluoresceinClass, jstring className)
{
	printf("Java_org_gontard_fluorescein_Fluorescein_printPathToRoot\n");
	gdata->classname = (char*)calloc(100, 1);
	strcpy(gdata->classname, env->GetStringUTFChars(className, 0));	
    dataDumpRequest(gdata->jvmti);
}
