#pragma once

#ifdef __cplusplus
extern "C" {
#endif

int spark_umh_init(void);
int spark_umh_apply(const char *connection_id, int force_input, int force_capture);
int spark_umh_release(const char *connection_id);
void spark_umh_shutdown(void);

#ifdef __cplusplus
}
#endif

