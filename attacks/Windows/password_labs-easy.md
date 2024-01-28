Examine the first target and submit the root password as the answer. 

1. Conducting preliminary scan on the target
2. discovered services `ftp`, `ssh`
3. Starting a brute force attack on the target on the ftp protocol using resources provided.
`hydra -L username.list -P password.list ftp://10.29.x.x`
Resulting in the discovery of the credentials `mike:7777777`
4. checking `.bash_history` resulting in the discovery of credentials for root `root:dgb6fzm0ynk@AME9pqu`