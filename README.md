# NtUserHook
Minimal kernel-usermode communication framework using a Win32k syscall hook (`NtUserXxx`).

## Syscall
In our case we're hooking (`NtUserGetPointerProprietaryId`), and the reason is that I liked the signature that takes only 2 params and this syscall is not a hotpath (not being called often by original Windows components which means no performance impact on the system).

You can change the syscall to any NtUserXxx you like by simply changing the pointers chain offsets and call type in both of usermode and kernel mode.

## Contribution
Feel free to open a PR if you wish to add/modify something
