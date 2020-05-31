import os
import sys
import subprocess
import signal


def drop_privileges(function):
    """
    Decorator to drop root privileges.
    """

    def inner(*args, **kwargs):
        # Get sudoer's UID
        try:
            sudo_uid = int(os.environ['SUDO_UID'])
        except (KeyError, ValueError):
            print("Could not get UID for sudoer", file=sys.stderr)
            return
        # Get sudoer's GID
        try:
            sudo_gid = int(os.environ['SUDO_GID'])
        except (KeyError, ValueError):
            print("Could not get GID for sudoer", file=sys.stderr)
            return
        # Make sure groups are reset
        try:
            os.setgroups([])
        except PermissionError:
            pass
        # Drop root
        os.setresgid(sudo_gid, sudo_gid, -1)
        os.setresuid(sudo_uid, sudo_uid, -1)
        # Execute function
        ret = function(*args, **kwargs)
        # Get root back
        os.setresgid(0, 0, -1)
        os.setresuid(0, 0, -1)
        return ret

    return inner


def which(binary):
    """
    Find a binary if it exists.
    """
    try:
        w = subprocess.Popen(
            ["which", binary], stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        res = w.stdout.readlines()
        if len(res) == 0:
            raise Exception(f"{binary} not found")
        return os.path.realpath(res[0].strip())
    except Exception:
        if os.path.isfile(binary):
            return os.path.realpath(binary)
        else:
            raise Exception(f"{binary} not found")


@drop_privileges
def run_binary(args_str, discard_output=False):
    """
    Drop privileges and run a binary if it exists.
    """
    # Wake up and do nothing on SIGCLHD
    signal.signal(signal.SIGUSR1, lambda x, y: None)
    # Reap zombies
    signal.signal(signal.SIGCHLD, lambda x, y: os.wait())
    args = args_str.split()
    try:
        binary = which(args[0])
    except Exception:
        return -1
    pid = os.fork()
    # Setup traced process
    if pid == 0:
        if discard_output:
            with open('/dev/null', 'w') as f:
                os.dup2(f.fileno(), sys.stdout.fileno(), inheritable=True)
                os.dup2(f.fileno(), sys.stderr.fileno(), inheritable=True)
        signal.pause()
        os.execvp(binary, args)
    # Return pid of traced process
    return pid
