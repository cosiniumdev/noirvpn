# Using noirvpn

This guide shows how to start the `noirvpn` service by hand on Linux, so that the desktop app can connect to it. Use it when you're not using a service manager (systemd, OpenRC, runit).

The desktop app does not create the tunnel itself; it relies on `noirvpn` for that. It will interface with the service through its control sockets. The service only accepts an app if your user is permitted to connect to the sockets.

Follow the steps below to give your user that acess.

## Before you start

- `sudo` or equivalent is required if not running as root; it is needed for the tunnel device and the routes.
- `/dev/net/tun` exists. If it is missing, run `sudo modprobe tun`.
- `noirvpn` and `noirvpn-desktop` are installed, or you have built from source or unpacked the release folder.

## Start the service with the noirvpn group

This is the usual setup. Every user in the group `noirvpn` can load a profile and connect from the desktop app.

1. Create the group:

   ```
   sudo groupadd --system noirvpn
   ```

2. Add your user to the group:

   ```
   sudo usermod -aG noirvpn $USER
   ```

3. Log out and log in again. The new group applies only to a new login.

4. Make sure that the group is there:

   ```
   id -nG
   ```

   The list must include `noirvpn`.

5. Start the service:

   ```
   sudo noirvpn
   ```

6. Start the desktop app as your normal user. It will detect the service and show your profiles.

> **Tip**: `sudo noirvpn-service` does steps 1 and 5 for you. It creates the group if it is missing, writes `/etc/noirvpn/service.conf` if that file does not exist, and then starts the service. You must still add your user to the group (step 2) and log in again (step 3).

### What the service uses when no config file is given

With no config file, `sudo noirvpn` starts a client service with these settings:

```
client-service
verb 3
datapath userspace
bus-control /run/noirvpn/desktop.control mode 0660 group noirvpn
bus-events  /run/noirvpn/desktop.events  mode 0660 group noirvpn
bus-allow uid 0 admin
bus-allow gid noirvpn operator
```

- Root is the administrator of the service.
- The members of `noirvpn` get the role `operator`: they may load a profile, connect, disconnect and read the status. The desktop app does not need anything extra.
- If the group `noirvpn` does not exist when the service starts, the service leaves out both group settings. Then only root can use the service, and the desktop app will show "No access to the service".

Options on the command line replace the default of the same name:

```
sudo noirvpn --verb 4
```

## Start the service for your user only

Use this when you do not want a `noirvpn` group. Specify your user name to `--allow-user`:

```
sudo noirvpn --allow-user $USER
```

Then start the desktop app as your normal user.

- The sockets belong to your user, with mode `0600` - only your user and root can connect.
- The user role is `operator`, the same as the members of `noirvpn` in the usual setup. Root stays the administrator.
- The folder `/run/noirvpn` gets mode `0755`.
- The setting applies to this run only and is not written to a config file.

## Start the service for another group

To grant access to the members of a group that already exists, specify its name to `--allow-group`:

```
sudo noirvpn --allow-group vpnusers
```

The sockets will set that group, with mode `0660`, and given the `operator` role.
You can set `--allow-user` and `--allow-group` together.

> **Note**: `--allow-user` and `--allow-group` are flags of `noirvpn` itself,
and they work on Linux and macOS. On Windows the installed service already
lets the users who are logged on connect.

## Keep the settings in a config file

To keep your settings, give a config file:

```
sudo noirvpn --config /etc/noirvpn/service.conf
```

If the file does not exist, `noirvpn` creates it from the defaults and from the options on the command line.
`noirvpn` never changes a file that exists.

A config file must contain the `bus-control`, `bus-events` and `bus-allow` lines shown above. A file with only `client-service` starts a root-only accessible service. You can add `--allow-user` or `--allow-group` to the command line of a config file too:

```
sudo noirvpn --config /etc/noirvpn/service.conf --allow-user $USER
```

`noirvpn` does not write these two flags into a new config file.

## Troubleshooting

### No access to the service, and /run/noirvpn belongs to root

**Problem**: The service runs, but the desktop app shows "No access to the service". `ls -ld /run/noirvpn` shows `drwxr-x--- root root`.

**Cause**: An earlier run of the service created `/run/noirvpn` without a group, for example a run before the group `noirvpn` existed. The service uses a folder that already exists as-is and does not change its group, because other noirvpn services on the same computer can use the same folder.

**Solution**: Do one of these:

- Stop the service and start it again with `--allow-user` or `--allow-group`. These flags change the folder so that your user can enter it:

  ```
  sudo noirvpn --allow-user $USER
  ```

- Change the folder to the group of your sockets while the service runs:

  ```
  sudo chgrp noirvpn /run/noirvpn
  ```

- Or stop the service, remove the folder, and start the service again:

  ```
  sudo rm -rf /run/noirvpn
  sudo noirvpn
  ```

  The folder is created again at start. `/run` is cleared at each restart of the computer.

To check the result, run `sudo ls -la /run/noirvpn`. The folder and the files `desktop.control` and `desktop.events` must have the group that your user is in.

### No access to the service after you added your user to the group

**Problem**: `sudo usermod -aG noirvpn $USER` worked, but the desktop app still shows "No access to the service".

**Solution**: Log out and log in again. The programs of your current login did not get the new group. Use `id -nG` to show the groups of your current login.

### The desktop app does not find the service

**Problem**: The desktop app shows "The noirvpn client service is not running".

**Solution**:

1. Make sure that the service runs: `pgrep -a noirvpn`.
2. Make sure that the control socket is in `/run/noirvpn`. If your config puts the socket in another place, start the app with that path:

   ```
   noirvpn-desktop --socket /path/to/NAME.control
   ```
3. Look at the output of the service, particularly for errors. The line "only root can use the control socket" means that no user or group was given access. Start the service with `--allow-user` or `--allow-group`, or create the group `noirvpn`.

## Related documentation

- [Service mode](docs/client.md#service-mode): profiles and connections through the control bus.
- [Management interface](docs/management.md): the sockets, the roles and `noirvpnctl`.
- [Option reference](docs/options.md): every option.
