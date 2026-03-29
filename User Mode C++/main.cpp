#include <windows.h>
#include <stdio.h>
#include "kernel_comm/kernel_comm.hpp"

int main() {
	KernelComm comm;
	if (!comm.Initialize()) {
		printf("Failed to initialize kernel communication\n");
		return -1;
	}

	if (!comm.AttachProcess(1234)) {
		printf("Failed to attach to process\n");
		return -1;
	}

	comm.Unhook();
}