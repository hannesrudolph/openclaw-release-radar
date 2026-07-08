#include <errno.h>
#include <inttypes.h>
#include <libproc.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/resource.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <unistd.h>

#define INITIAL_PID_SLACK 16U
#define MAX_PID_CAPACITY 131072U
#define MAX_LIST_ATTEMPTS 6U
#define PROCESS_NAME_CAPACITY ((2U * MAXCOMLEN) + 1U)

static int write_json_string(const char *value);

static void read_process_command(
  pid_t pid,
  const char *fallback,
  char *command,
  size_t command_capacity
) {
  int mib[3] = {CTL_KERN, KERN_PROCARGS2, pid};
  size_t buffer_size = 0;
  char *buffer = NULL;
  char *cursor;
  char *end;
  size_t command_length;

  snprintf(command, command_capacity, "%s", fallback);
  command[command_capacity - 1U] = '\0';
  if (
    sysctl(mib, 3U, NULL, &buffer_size, NULL, 0U) != 0 ||
    buffer_size <= sizeof(int) ||
    buffer_size > (size_t)ARG_MAX
  ) {
    return;
  }
  buffer = malloc(buffer_size);
  if (buffer == NULL) {
    return;
  }
  if (sysctl(mib, 3U, buffer, &buffer_size, NULL, 0U) != 0) {
    free(buffer);
    return;
  }
  cursor = buffer + sizeof(int);
  end = buffer + buffer_size;
  while (cursor < end && *cursor != '\0') {
    cursor++;
  }
  while (cursor < end && *cursor == '\0') {
    cursor++;
  }
  if (cursor >= end) {
    free(buffer);
    return;
  }
  command_length = strnlen(cursor, (size_t)(end - cursor));
  if (command_length == 0U || command_length >= (size_t)(end - cursor)) {
    free(buffer);
    return;
  }
  if (command_length >= command_capacity) {
    command_length = command_capacity - 1U;
  }
  memcpy(command, cursor, command_length);
  command[command_length] = '\0';
  free(buffer);
}

static int fail_errno(const char *operation, int error_number) {
  fprintf(stderr, "%s: %s\n", operation, strerror(error_number));
  return 1;
}

static int compare_pids(const void *left, const void *right) {
  const pid_t left_pid = *(const pid_t *)left;
  const pid_t right_pid = *(const pid_t *)right;
  return (left_pid > right_pid) - (left_pid < right_pid);
}

static int parse_process_group(const char *value, pid_t *process_group) {
  char *end = NULL;
  long parsed;

  errno = 0;
  parsed = strtol(value, &end, 10);
  if (
    errno != 0 ||
    end == value ||
    *end != '\0' ||
    parsed <= 0 ||
    parsed > INT_MAX
  ) {
    return -1;
  }
  *process_group = (pid_t)parsed;
  return 0;
}

static int emit_process_identity(pid_t pid) {
  struct proc_bsdinfo info;
  char command[PROC_PIDPATHINFO_MAXSIZE];
  const char *fallback;
  int result;

  memset(&info, 0, sizeof(info));
  errno = 0;
  result = proc_pidinfo(
    (int)pid,
    PROC_PIDTBSDINFO,
    0,
    &info,
    (int)sizeof(info)
  );
  if (result != (int)sizeof(info)) {
    return fail_errno(
      "proc_pidinfo(PROC_PIDTBSDINFO)",
      errno == 0 ? ESRCH : errno
    );
  }
  if (
    info.pbi_pid != (uint32_t)pid ||
    info.pbi_ppid > (uint32_t)INT_MAX ||
    info.pbi_pgid == 0U ||
    info.pbi_pgid > (uint32_t)INT_MAX
  ) {
    fprintf(stderr, "process identity is malformed\n");
    return 1;
  }

  fallback = info.pbi_comm[0] == '\0' ? info.pbi_name : info.pbi_comm;
  read_process_command(pid, fallback, command, sizeof(command));
  if (
    printf(
      "{\"schemaVersion\":1,\"pid\":%d,\"parentPid\":%u,"
      "\"processGroupPid\":%u,\"startedAt\":\"%" PRIu64
      ".%06" PRIu64 "\",\"command\":",
      pid,
      info.pbi_ppid,
      info.pbi_pgid,
      (uint64_t)info.pbi_start_tvsec,
      (uint64_t)info.pbi_start_tvusec
    ) < 0 ||
    write_json_string(command) != 0 ||
    fputs("}\n", stdout) == EOF ||
    fflush(stdout) == EOF
  ) {
    return fail_errno("write(stdout)", errno == 0 ? EIO : errno);
  }
  return 0;
}

static int list_process_group_pids(
  pid_t process_group,
  pid_t **pids_out,
  size_t *count_out
) {
  pid_t *pids = NULL;
  size_t capacity = 0;
  unsigned int attempt;

  for (attempt = 0; attempt < MAX_LIST_ATTEMPTS; attempt++) {
    int required;
    int count;
    size_t requested;
    pid_t *resized;

    errno = 0;
    /* libproc returns a PID count; only the buffer argument is byte-sized. */
    required = proc_listpgrppids(process_group, NULL, 0);
    if (required < 0 || (required == 0 && errno != 0)) {
      free(pids);
      return fail_errno(
        "proc_listpgrppids(size)",
        errno == 0 ? EIO : errno
      );
    }
    if ((size_t)required > MAX_PID_CAPACITY) {
      free(pids);
      fprintf(stderr, "process group PID list exceeds the safety limit\n");
      return 1;
    }

    requested = (size_t)required + INITIAL_PID_SLACK;
    if (requested < capacity * 2U) {
      requested = capacity * 2U;
    }
    if (requested < INITIAL_PID_SLACK) {
      requested = INITIAL_PID_SLACK;
    }
    if (requested > MAX_PID_CAPACITY) {
      requested = MAX_PID_CAPACITY;
    }
    if (requested > (size_t)INT_MAX / sizeof(*pids)) {
      free(pids);
      fprintf(stderr, "process group PID buffer is too large\n");
      return 1;
    }

    if (requested != capacity) {
      resized = realloc(pids, requested * sizeof(*pids));
      if (resized == NULL) {
        int allocation_error = errno == 0 ? ENOMEM : errno;
        free(pids);
        return fail_errno("realloc(process group PIDs)", allocation_error);
      }
      pids = resized;
      capacity = requested;
    }

    errno = 0;
    count = proc_listpgrppids(
      process_group,
      pids,
      (int)(capacity * sizeof(*pids))
    );
    if (count < 0 || (count == 0 && errno != 0)) {
      free(pids);
      return fail_errno(
        "proc_listpgrppids(snapshot)",
        errno == 0 ? EIO : errno
      );
    }
    if ((size_t)count > capacity) {
      free(pids);
      fprintf(stderr, "proc_listpgrppids returned an invalid PID count\n");
      return 1;
    }
    if ((size_t)count < capacity) {
      *pids_out = pids;
      *count_out = (size_t)count;
      return 0;
    }
  }

  free(pids);
  fprintf(stderr, "process group PID list did not stabilize\n");
  return 1;
}

static int write_json_string(const char *value) {
  const unsigned char *cursor = (const unsigned char *)value;

  if (putchar('"') == EOF) {
    return -1;
  }
  while (*cursor != '\0') {
    unsigned char byte = *cursor++;
    if (byte == '"' || byte == '\\') {
      if (putchar('\\') == EOF || putchar((int)byte) == EOF) {
        return -1;
      }
    } else if (byte >= 0x20U && byte <= 0x7eU) {
      if (putchar((int)byte) == EOF) {
        return -1;
      }
    } else if (printf("\\u%04x", (unsigned int)byte) < 0) {
      return -1;
    }
  }
  return putchar('"') == EOF ? -1 : 0;
}

static int emit_snapshot(pid_t process_group) {
  pid_t *pids = NULL;
  size_t pid_count = 0;
  size_t index;
  int first = 1;

  if (list_process_group_pids(process_group, &pids, &pid_count) != 0) {
    return 1;
  }
  if (pid_count > 1U) {
    qsort(pids, pid_count, sizeof(*pids), compare_pids);
  }

  if (
    printf(
      "{\"schemaVersion\":1,\"processGroupPid\":%d,\"processes\":[",
      process_group
    ) < 0
  ) {
    free(pids);
    return fail_errno("write(stdout)", errno);
  }

  for (index = 0; index < pid_count; index++) {
    struct rusage_info_v4 usage;
    char process_name[PROCESS_NAME_CAPACITY];
    char process_path[PROC_PIDPATHINFO_MAXSIZE];
    int name_length;
    int path_length;
    int error_number;
    pid_t pid = pids[index];

    if (pid <= 0 || (index > 0 && pid == pids[index - 1])) {
      continue;
    }

    memset(&usage, 0, sizeof(usage));
    errno = 0;
    if (
      proc_pid_rusage(
        (int)pid,
        RUSAGE_INFO_V4,
        (rusage_info_t *)&usage
      ) != 0
    ) {
      error_number = errno;
      if (error_number == ESRCH) {
        continue;
      }
      memset(process_path, 0, sizeof(process_path));
      path_length = proc_pidpath(
        (int)pid,
        process_path,
        (uint32_t)sizeof(process_path)
      );
      if (path_length <= 0) {
        snprintf(
          process_path,
          sizeof(process_path),
          "%s",
          "<unavailable>"
        );
      }
      process_path[sizeof(process_path) - 1U] = '\0';
      free(pids);
      fprintf(
        stderr,
        "proc_pid_rusage(pid=%d,path=%s): %s\n",
        pid,
        process_path,
        strerror(error_number)
      );
      return 1;
    }

    memset(process_name, 0, sizeof(process_name));
    errno = 0;
    name_length = proc_name(
      (int)pid,
      process_name,
      (uint32_t)sizeof(process_name)
    );
    if (name_length <= 0) {
      process_name[0] = '\0';
    }
    process_name[sizeof(process_name) - 1U] = '\0';

    if (!first && putchar(',') == EOF) {
      free(pids);
      return fail_errno("write(stdout)", errno);
    }
    first = 0;
    if (
      printf(
        "{\"pid\":%d,\"ri_proc_start_abstime\":\"%" PRIu64
        "\",\"ri_diskio_byteswritten\":\"%" PRIu64
        "\",\"processName\":",
        pid,
        usage.ri_proc_start_abstime,
        usage.ri_diskio_byteswritten
      ) < 0 ||
      write_json_string(process_name) != 0 ||
      putchar('}') == EOF
    ) {
      free(pids);
      return fail_errno("write(stdout)", errno);
    }
  }

  free(pids);
  if (fputs("]}\n", stdout) == EOF || fflush(stdout) == EOF) {
    return fail_errno("write(stdout)", errno);
  }
  return 0;
}

int main(int argc, char **argv) {
  pid_t process_group;

  if (argc == 3 && strcmp(argv[1], "--identity") == 0) {
    if (parse_process_group(argv[2], &process_group) != 0) {
      fprintf(stderr, "process identity PID must be a positive decimal pid_t\n");
      return 64;
    }
    return emit_process_identity(process_group);
  }
  if (argc != 2) {
    fprintf(
      stderr,
      "usage: %s <positive-pgid>|--self-check|--identity <positive-pid>\n",
      argv[0]
    );
    return 64;
  }
  if (strcmp(argv[1], "--self-check") == 0) {
    process_group = getpgrp();
    if (process_group <= 0) {
      return fail_errno("getpgrp", errno == 0 ? EIO : errno);
    }
  } else if (parse_process_group(argv[1], &process_group) != 0) {
    fprintf(stderr, "process group must be a positive decimal pid_t\n");
    return 64;
  }
  return emit_snapshot(process_group);
}
