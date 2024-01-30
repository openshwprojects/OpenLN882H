import os
import sys
import subprocess


def read_flash(filename, arg_port, flash_size, is_otp = False):
    flash_addr = 0x00000000
    
    if is_otp:
         start_tag = 'flash otp data:'
    else:
         start_tag = 'flash data:'

    with open(filename, "wb") as flash_file:
        while flash_addr < flash_size:
            flash_hex_addr = hex(flash_addr)
            if is_otp:
                flash_hex = subprocess.run(['LN882H_CMD_Tool.exe', arg_port, 'flash', 'otp', 'read', flash_hex_addr, '0x100'], capture_output=True, text=True).stdout
            else:
                flash_hex = subprocess.run(['LN882H_CMD_Tool.exe', arg_port, 'flash', 'read', flash_hex_addr, '0x100'], capture_output=True, text=True).stdout 
            if flash_hex.startswith(start_tag) and flash_hex.endswith('\nOk.'):
                flash_hex = flash_hex.replace('\nOk.', '')
                flash_hex = flash_hex.replace(start_tag, '')
                bin = bytearray.fromhex(flash_hex)
                flash_file.write(bin)
                print('.', end='', flush=True)
                flash_addr += 0x100
            else:
                print('Error: ' + flash_hex)
                os._exit(1)
        print('')
        print('complete.')

if __name__ == '__main__':
        print ('LN882H flash dump tool v1.0')
        if len(sys.argv) < 3:
                print('Usage: python dumpflash.py port filename <length>')
                print('       port: e.g. COM6')
                print('       filename: any simple name e.g. test')
                print('                 otp_ and flash_ files will be created as:')
                print('                 otp_filename.bin')
                print('                 flash_filename.bin')
                print('       length: optional: the amount of flash to dump. This MUST be a hex value.')
                print('               e.g. 0x00040000 (256 KB)')
                print('               If length is omited dumping will continue until 0xFFFFFFFF or an error occurs')
                print('               OTP is fixed size and will always dump 1KB')
                print('')
                os._exit(0)

        arg_port = sys.argv[1]
        filename = sys.argv[2]
        if (len(sys.argv) > 3):
            flash_size = int(sys.argv[3], 16)
        else:
            flash_size = 0xFFFFFFFF
        flash_addr = 0x00000000

        # load RAMCode so that we can access flash
        print('Loading RAMCode...')
        flash_hex = subprocess.run(['LN882H_CMD_Tool.exe', arg_port, 'flash', 'read_with_download', '0x0', '0x100'], capture_output=True, text=True).stdout
        if flash_hex.startswith('flash data:') and flash_hex.endswith('\nOk.'):
             print('Flash RAMCode loaded OK.')
        else:
            print('Error: ' + flash_hex)
            os._exit(1)

        # dump flash OTP (1KB = 0x400)
        otp_file = filename + "_otp.bin"
        print('Dumping flash OTP to ' + otp_file + ':')
        read_flash(otp_file, arg_port, 0x00000400, True)
        
        # dump flash
        flash_file = filename + '_flash.bin'
        print('Dumping flash (size: '+ hex(flash_size) + ') to ' + flash_file + ':')
        read_flash(flash_file, arg_port, flash_size)







