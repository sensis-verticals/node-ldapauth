// Provides Node.JS binding for ldap_simple_bind().
// See README
// 2010, Joe Walnes, joe@walnes.com, http://joewalnes.com/


/*
Here's the basic flow of events. LibEIO is used to ensure that
the LDAP calls occur on a background thread and do not block
the main Node event loop.

 +----------------------+                +------------------------+
 | Main Node Event Loop |                | Background Thread Pool |
 +----------------------+                +------------------------+

      User application
             |
             V
    JavaScript: authenticate()
             |
             V
    ldapauth.cc: Authenticate()
             |
             +-------------------------> libauth.cc: EIO_Authenticate()
             |                                      |
             V                                      V
      (user application carries               ldap_simple_bind()
       on doing its stuff)                          |
             |                              (wait for response
       (no blocking)                           from server)
             |                                      |
     (sometime later)                         (got response)
             |                                      |
    ldapauth.cc: EIO_AfterAuthenticate() <----------+
             |
             V
Invoke user supplied JS callback

*/

#include <v8.h>
#include <node.h>
#include <node_events.h>
#include <ldap.h>
#include <unistd.h>
#include <stdlib.h>

using namespace v8;

#define THROW(message) ThrowException(Exception::TypeError(String::New(message)))

// Data passed between threads
struct auth_request 
{
  // Input params
  char *host;
  int port;
  char *username;
  char *password;
  char *groups;
  // Callback function
  Persistent<Function> callback;
  // Result
  bool connected;
  bool authenticated;
};

// Runs on background thread, performing the actual LDAP request.
static int EIO_Authenticate(eio_req *req) 
{
  struct auth_request *auth_req = (struct auth_request*)(req->data);

  // Node: OpenLDAP does actually provide _some_ async API calls,
  // But ldap_open does NOT have an async equivalent, so we have to
  // do this in a background thread. Seeing as we're in a background
  // thread anyway, it's just simpler to call the rest of the calls
  // synchronously.
  
  // Connect to LDAP server
  LDAP *ldap = ldap_open(auth_req->host, auth_req->port);
  if (ldap == NULL) {
    auth_req->connected = false;
    auth_req->authenticated = false;
  } else {
    // Bind with credentials, passing result into auth_request struct
    int ldap_result = ldap_simple_bind_s(ldap, auth_req->username, auth_req->password);
    //fprintf(stderr, "authenticated with ldap\n");
    if (ldap_result == LDAP_SUCCESS) {
        char *filter;
        asprintf(&filter, "(member=%s)", auth_req->username);
        //fprintf(stderr, "Using this filter: %s\n", filter);
        LDAPMessage *searchResult;
        int search_success = ldap_search_ext_s(ldap, auth_req->groups, LDAP_SCOPE_SUBTREE, filter, NULL, 0, NULL, NULL, NULL, LDAP_NO_LIMIT, &searchResult);
        //fprintf(stderr, "search done with search_success = %i, LDAP_SUCCESS = %i\n", search_success, LDAP_SUCCESS);
        //fprintf(stderr, "ldap_count_entries = %i\n", ldap_count_entries(ldap, searchResult));
        auth_req->authenticated = (search_success == LDAP_SUCCESS) && (ldap_count_entries(ldap, searchResult) > 0);
        free(filter);
        ldap_msgfree(searchResult);
    } else {
      auth_req->authenticated = false;
    }
    // Disconnect
    ldap_unbind(ldap);

    //fprintf(stderr, "leaving the ldap parts now with auth_req->authenticated = %i\n", auth_req->authenticated);
    auth_req->connected = true;
  }
  
  return 0;
}

// Called on main event loop when background thread has completed
static int EIO_AfterAuthenticate(eio_req *req) 
{
  ev_unref(EV_DEFAULT_UC);
  HandleScope scope;
  struct auth_request *auth_req = (struct auth_request *)(req->data);

  //fprintf(stderr, "In after authenticate, with auth_req->connected = %i, auth_req->authenticated = %i\n", auth_req->connected, auth_req->authenticated);
  
  // Invoke callback JS function
  Handle<Value> callback_args[2];
  callback_args[0] = auth_req->connected ? (Handle<Value>)Undefined() : Exception::Error(String::New("LDAP connection failed"));
  callback_args[1] = Boolean::New(auth_req->authenticated);
  //fprintf(stderr, "just before the js callback\n");
  auth_req->callback->Call(Context::GetCurrent()->Global(), 2, callback_args);
  //fprintf(stderr, "after the js callback\n");
  // Cleanup auth_request struct
  auth_req->callback.Dispose();
  free(auth_req);

  return 0;
}

// Exposed authenticate() JavaScript function
static Handle<Value> Authenticate(const Arguments& args)
{
  HandleScope scope;
  
  // Validate args.
  if (args.Length() < 6)      return THROW("Required arguments: ldap_host, ldap_port, username, password, groups, callback");
  if (!args[0]->IsString())   return THROW("ldap_host should be a string");
  if (!args[1]->IsInt32())    return THROW("ldap_port should be a string");
  if (!args[2]->IsString())   return THROW("username should be a string");
  if (!args[3]->IsString())   return THROW("password should be a string");
  if (!args[4]->IsString())   return THROW("groups should be a string");
  if (!args[5]->IsFunction()) return THROW("callback should be a function");

  // Input params.
  String::Utf8Value host(args[0]);
  int port = args[1]->Int32Value();
  String::Utf8Value username(args[2]);
  String::Utf8Value password(args[3]);
  String::Utf8Value groups(args[4]);
  Local<Function> callback = Local<Function>::Cast(args[5]);

  
  // Store all parameters in auth_request struct, which shall be passed across threads.
  struct auth_request *auth_req = (struct auth_request*) calloc(1, sizeof(struct auth_request));
  auth_req->host = strdup(*host);
  auth_req->port = port;
  auth_req->username = strdup(*username);
  auth_req->password = strdup(*password);
  auth_req->groups = strdup(*groups);
  auth_req->callback = Persistent<Function>::New(callback);
  
  // Use libeio to invoke EIO_Authenticate() in background thread pool
  // and call EIO_AfterAuthententicate in the foreground when done
  eio_custom(EIO_Authenticate, EIO_PRI_DEFAULT, EIO_AfterAuthenticate, auth_req);
  ev_ref(EV_DEFAULT_UC);

  return Undefined();
}

// Entry point for native Node module
extern "C" void
init (Handle<Object> target) 
{
  HandleScope scope;
  target->Set(String::New("authenticate"), FunctionTemplate::New(Authenticate)->GetFunction());
}
