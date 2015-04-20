#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>


int main(int argc, char *argv[])
{
	pid_t pid;

	if ((pid = fork()) < 0)
		exit(1);

	if (!pid) {
		char *buf = "hi\n";
		FILE *f = fopen(argv[1], "w");
		fwrite(buf, 1, 3, f);
		fclose(f);
		exit(0);
	}
	sleep(3);
	kill(pid, SIGTERM);
	kill(pid, SIGKILL);
	wait(NULL);
	printf("done\n");
}

