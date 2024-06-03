# LXD

***Ref***: 
	[LXC/LXD vs Docker Which is better?](https://www.youtube.com/watch?v=Q5J9N67z_SM)

It provides a hypervisor service that allows to create and manage the containers.

## Creating a container

### Step 1 - Configure LXD

1. Take a user that is already part of the `lxd` group or add them using:

```sh
sudo usermod --append --groups lxd sammy
```

2. (Optional) It is recommended to use `zfs` filesystem as a storage backend for LXD as the containers are stored either in a pre-allocated file. Install `zfsutils-linux` package.

```sh
sudo apt-get update
sudo apt-get install zfsutils-linux
```

3. Start the initialization process.

```sh
sudo lxd init
```

4. Recommended Configurations for the following prompts

```shell-session
Do you want to configure a new storage pool (yes/no) [default=yes]? yes
Name of the storage backend to use (dir or zfs) [default=dir]: dir
Would you like LXD to be available over the network (yes/no) [default=no]? no
Do you want to configure the LXD bridge (yes/no) [default=yes]? yes
```

### Step 2 - Configuring Networking

#### Bridge configuration

- If the answer was no to the prompt:
```
Would you like LXD to be available over the network (yes/no) [default=no]?
```

- Then it prompts
```
Do you want to configure the LXD bridge (yes/no) [default=yes]?
```
- If the answer was `yes`
	- Then it enables the following features
		- Each Container gets a private IP
		- The containers can now communicate with each other over the private network
		- Each container can now initiate connections to the internet
		- The containers created will remain inaccessible from the internet, i.e. inbound requests from the internet to the container will not reach unless specified explicitly

![[dialog_lxd_bridge.png]]

1. Confirm the action to set up the bridge
2. Name the bridge
3. Configure the addressing of atleast IPv4
4. Configure the default DHCP values
5. Select `yes` when asked to NAT the IPv4 traffic
6. Select `no` for IPv6 unless required

## Step 3 - Importing the local image

- To view the list of available containers use:

```sh
lxc list
```

- Import the image

```shell-session
lxc image import alpine.tar.gz alpine.tar.gz.root --alias alpine
```

