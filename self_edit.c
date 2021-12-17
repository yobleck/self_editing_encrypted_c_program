//gcc self_edit.c -lcrypt -lgcrypt -o self_edit
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <gcrypt.h>

void print_help(){
    printf("HELP:\nr: to read hex data for file\nw: + string arg to write data to temp file");
}

void main(int argc, char *argv[]){
    
    char* pswd = crypt(getpass("input pass here:\n"), "$6$sult"); //$6$=sha512 TODO: $rounds=xxx$
    //printf("%s\n", pswd); //https://man7.org/linux/man-pages/man3/crypt.3.html
    
    if(!strcmp(pswd, "$6$sult$Q0XzRqWLhxukRtFI4X1eG.As0I2EGR8rXro/KiCDaPw1va46zi.Y5nvtPsXLAl9X7TZj5WAs6WOHbB7rtfgl01")){ //pass = pass
        
        //initialize gcrypt
        char* ini_vec = "a test ini value"; //WARNING: this shouldn't be hard coded
        char* key = "this is a key. 0123456789abcdefg"; //WARNING: this shouldn't be hard coded https://gnupg.org/documentation/manuals/gcrypt/Key-Derivation.html
        size_t key_len = gcry_cipher_get_algo_keylen(GCRY_CIPHER_AES256);
        printf("key len: %d\n", gcry_cipher_get_algo_keylen(GCRY_CIPHER_AES256));
        size_t blk_len = gcry_cipher_get_algo_blklen(GCRY_CIPHER_AES256);
        printf("blk len: %d\n", gcry_cipher_get_algo_blklen(GCRY_CIPHER_AES256));
        
        gcry_cipher_hd_t handle;
        gcry_error_t error = 0;
        
        //disable rdrand because its broken on amd ryzen
        gcry_control(GCRYCTL_DISABLE_HWF, "intel-rdrand", NULL);
        //check version
        const char* version = gcry_check_version(NULL);
        printf("gcrypt version: %s\n", version);
        //disable secure memory
        gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
        //finished init
        gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
        
        
        if(argc >= 2){ //start arg handling
            
            //read text at end of file
            if(!strcmp(argv[1],"r")){
                
                FILE *f = fopen("./self_edit", "rb");
                
                //get file size
                fseek(f, 0L, SEEK_END);
                int size_f = ftell(f);
                printf("file size: %d\n", size_f);
                rewind(f);
                
                //put file in char array buffer thing
                char buf[size_f];
                fread(buf, sizeof(char), size_f, f);
                
                //scan file for message header: "i" x8
                int msg_index = 0;
                for(int i = 0; i < size_f; i++){
                    if(buf[i] == 'i'){ //!strcmp(buf[i], 'i')
                        if(buf[i+1] == 'i' && buf[i+2] == 'i' && buf[i+3] == 'i' && buf[i+4] == 'i' &&
                           buf[i+5] == 'i' && buf[i+6] == 'i' && buf[i+7] == 'i'){
                            msg_index = i+8;
                            //break here?
                        }
                    }
                }
                if (msg_index == 0){
                    msg_index = size_f;
                    printf("no header found\n");
                }
                else{
                    //write file contents to stdout as hex
                    printf("hidden text:\n");
                    for(int i = msg_index; i < size_f; i++){
                        printf("%x ", (unsigned int)(unsigned char)buf[i]);
                        if(i%16 == 0 && i != 0){
                            printf("\n");
                        }
                    }
                    printf("\n");
                    
                    //decrypt file
                    printf("temp size: %d\n", sizeof(buf)/sizeof(buf[0])-msg_index);
                    size_t temp_size = (size_t) sizeof(buf)/sizeof(buf[0])-msg_index; //16
                    rewind(f);
                    fseek(f, msg_index, SEEK_SET);
                    char encrypt_r[temp_size];
                    fread(encrypt_r, temp_size, 1, f);
                    printf("hidden text 2: %s\n", encrypt_r);
                    char* output = malloc(temp_size);
                    
                    error = gcry_cipher_open(&handle, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC, 0);
                    printf("open error: "); printf(gcry_strerror(error)); printf("\n");
                    
                    error = gcry_cipher_setkey(handle, key, key_len);
                    printf("key error: "); printf(gcry_strerror(error)); printf("\n");
                    
                    error = gcry_cipher_setiv(handle, ini_vec, blk_len);
                    printf("block error: "); printf(gcry_strerror(error)); printf("\n");
                    
                    error = gcry_cipher_decrypt(handle, output, temp_size, encrypt_r, temp_size);
                    printf("decrypt error: "); printf(gcry_strerror(error)); printf("\n");
                    printf("decrypted text: %s\n", output);
                    for(int i = 0; i < strlen(output); i++){
                        printf("%x ", (unsigned int)(unsigned char)output[i]); //https://stackoverflow.com/questions/18497845/
                    }
                    
                    gcry_cipher_close(handle);
                }
                fclose(f);
            }
            
            
            //write text to end of file
            else if(!strcmp(argv[1], "w")){
                if(argc == 3){
                    
                    //encrypt input
                    size_t padding = ((strlen(argv[2])/16)+1)*16-1;
                    char* input = malloc(padding); //all this is to make sure num_chrs % 16 == 0
                    printf("str len w/ pad: %d\n", padding);
                    memset(input, '=', padding); //TODO: need better filler character https://stackoverflow.com/questions/13572253/
                    memcpy(input, argv[2], strlen(argv[2]));
                    //printf("%d", strlen(input));
                    printf("\n");

                    size_t input_len = strlen(input)+1;
                    char* encrypt = malloc(input_len);
                    
                    error = gcry_cipher_open(&handle, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC, 0);
                    printf("open error: "); printf(gcry_strerror(error)); printf("\n");
                    
                    error = gcry_cipher_setkey(handle, key, key_len);
                    printf("key error: "); printf(gcry_strerror(error)); printf("\n");
                    
                    error = gcry_cipher_setiv(handle, ini_vec, blk_len);
                    printf("block error: "); printf(gcry_strerror(error)); printf("\n");
                    
                    error = gcry_cipher_encrypt(handle, encrypt, input_len, input, input_len);
                    printf("encrypt error: "); printf(gcry_strerror(error)); printf("\n");
                    printf("encrypted text: ");
                    for(int i = 0; i < strlen(encrypt); i++){
                        printf("%x ", (unsigned int)(unsigned char)encrypt[i]);
                    }
                    
                    
                    gcry_cipher_close(handle);
                    printf("\n\n");
                    
                    //write input to file
                    //open file 1 and get file size
                    FILE* f = fopen("./self_edit", "rb");
                    fseek(f, 0L, SEEK_END);
                    int f_size = ftell(f);
                    printf("size of input file: %d\n", f_size);
                    rewind(f);
                    
                    //create file 2 and set size to file 1 + input arg len
                    //https://stackoverflow.com/questions/7775027/how-to-create-file-of-x-size
                    FILE* f2 = fopen("./output", "wb");
                    int f_size_out = f_size +8+strlen(encrypt);
                    fseek(f2, f_size_out, SEEK_SET); // does this do anything?
                    //fputc('\0', f2); //terminating null?
                    rewind(f2);
                    printf("size of output file: %d\n", f_size_out);
                    
                    //buffer of chars from f1
                    char buf[f_size_out];
                    fread(buf, sizeof(char), f_size, f);
                    
                    //buffer of chars from argv[2]
                    char chr_to_f2[8+strlen(encrypt)];
                    strcpy(chr_to_f2, "iiii"); //header for text section at end of file
                    strcat(chr_to_f2, "iiii"); //stops "i" x8 from showing up in binary file
                    strcat(chr_to_f2, encrypt);
                    printf("encrypted input: %s\n", chr_to_f2 + 8);
                    
                    //add argv[2] to buf
                    for (int i = f_size; i < f_size_out; i++){
                        buf[i] = chr_to_f2[i-f_size];
                    }
                    
                    //write to f2
                    fwrite(buf, sizeof(buf), 1, f2);
                    
                    fclose(f);
                    fclose(f2);
                    
                    /*FILE* f_txt = fopen("./e_text", "w");
                    for (int i = 0; i < strlen(encrypt); i++){
                        fwrite(&encrypt[i], sizeof(encrypt[i]), 1, f_txt);
                    }
                    fclose(f_txt);*/
                    printf("remember to manually rename output to desired name\n");
                }
                
                else{
                    printf("no string inputted or too many args\n");
                }
            }
            
            
            else if(!strcmp(argv[1],"h") || !strcmp(argv[1],"-h") || !strcmp(argv[1],"--help")){
                print_help();
            }
            else{
                print_help();
            }
        } //end argc check
        else{
            print_help();
        }
    } //end pass check
    else{
        printf("ERROR: password did not match\n");
        print_help();
    }
}
