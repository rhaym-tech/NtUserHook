#include <stdio.h>
#include "kernel_comm/kernel_comm.h"

int main() {
	KernelComm* comm = KernelComm_Create();

	if (!comm) {
		printf("Failed to create KernelComm instance\n");
		return -1;
	}

	if (!KernelComm_Initialize(comm)) {
		printf("Failed to initialize kernel communication\n");
		KernelComm_Destroy(comm);
		return -1;
	}

	if (!KernelComm_AttachProcess(comm, 1234)) {
		printf("Failed to attach to process\n");
		KernelComm_Destroy(comm);
		return -1;
	}

	printf("Press Enter to trigger bug check...");
	getchar();

	KernelComm_TriggerBugCheck(comm);
}