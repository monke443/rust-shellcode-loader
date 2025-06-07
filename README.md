# rust-shellcode-loader
Loader written in rust that injects shellcode into a remote process through NtMapViewOfSection and NtCreateThreadEx. Uses dynamic exports through a Hells Gate crate wrapper I found from 0xflux ![here](https://github.com/0xflux/Rust-Hells-Gate). Calls ExitThread to prevent crashing if shellcode doesn't call it, but I dont think i got that part quite right. 

Anyways, works.

https://github.com/user-attachments/assets/043c61d1-4706-45a9-9cc6-bd1e29da4ea4

