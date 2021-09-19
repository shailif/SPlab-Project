#include <stdio.h>
#include <stdlib.h>
#include <stdio_ext.h>
#include <string.h>
#include <stdbool.h>

char endian;
typedef struct virus{
    unsigned short SigSize;
    char virusName[16];
    unsigned char* sig;
}virus;

typedef struct link link;
struct link{
    link *nextVirus;
    virus *vir;
};

void PrintHex(FILE* output, unsigned char *buffer, long length);
virus *readVirus(FILE* file);
void printVirus(virus* virus, FILE* output);
void list_print(link *virus_list, FILE* file);
link* list_append(link* virus_list, virus* data);
void list_free(link *virus_list);
int list_size(link *virus_list);
link* link_by_index(link *virus_list, int index);
void loadSignatures(link** virus_list_pointer);
void printSignatures (link** virus_list_pointer);
void detect_virus(char *buffer, unsigned int size, link *virus_list, FILE* output);
void detectViruses(link** virus_list_pointer,char *argv1);
void kill_virus(char *fileName, int signitureOffset, int signitureSize);
void fixFile(link** virus_list_pointer,char *argv1);


struct fun_desc {
    char *name;
    void (*fun)();
};

int main(int argc, char **argv) {
    link *virus_list=NULL;
    struct fun_desc menu[] = { { "Load signatures", loadSignatures }, { "Print signatures",  printSignatures }, {"Detect viruses", detectViruses}, {"Fix file",fixFile}, { NULL, NULL } };
    int size = sizeof(menu) / sizeof(struct fun_desc) - 1;
    while (1) {
        printf("Please choose a function:\n");
        for (int i = 0; i < size; i++)
            printf("%d) %s\n", i+1, menu[i].name);
        printf("option: ");
        char func[4];
        fgets(func, 4, stdin);
        int funcint;
        sscanf(func, "%d", &funcint);
        __fpurge(stdin);

        if (funcint > 0 & funcint < 5)
            printf("Within bounds\n");
        else {
            printf("Not within bounds\n");
            list_free(virus_list);
            exit(0);
        }
        link **virus_list_pointer=NULL;
        virus_list_pointer=&virus_list;       
        menu[funcint-1].fun(virus_list_pointer,argv[1]);     
    }
}


/*  This function prints length bytes from buffer in hexa. */
void PrintHex(FILE* output, unsigned char *buffer, long length) {
    for (int i=0; i<length; i++)
        fprintf(output,"%02X " ,buffer[i]);
    fputc('\n',output);
    fputc('\n',output);
}

/*  This function receives a file pointer and returns a virus*
    that represents the next virus in the file. */
virus *readVirus(FILE* file){
    if(feof(file))
        return NULL;
    virus *myvirus=malloc(sizeof(struct virus));
    myvirus->SigSize=0;
    myvirus->sig=NULL;
       
    fread(myvirus,1,18,file);//SigSize and virusName
    if(endian=='B')
        myvirus->SigSize=((myvirus->SigSize>>8)&0xff) | ((myvirus->SigSize<<8)&0xff00);
    myvirus->sig=malloc(myvirus->SigSize);
    fread(myvirus->sig,1,myvirus->SigSize,file);
    return myvirus;
}

void printVirus(virus* virus, FILE* output){
    fprintf(output,"Virus name: %s\n",virus->virusName);
    fprintf(output,"Virus size: %d\n",virus->SigSize);
    fprintf(output,"signature:\n");
    PrintHex(output,virus->sig,virus->SigSize);
}

/*  Print the data of every link in the list to the given stream. */
void list_print(link *virus_list, FILE* file) {
    link *curr = virus_list;
    while (curr!=NULL) {
        printVirus(curr->vir, file);
        curr=curr->nextVirus;
    }
}

/*  Add a new link with the given data to the list 
    and return a pointer to the list (i.e., the first link in the list). */
link* list_append(link* virus_list, virus* data){
    if(virus_list==NULL){
        virus_list=malloc(sizeof(link));
        virus_list->nextVirus=NULL;
        virus_list->vir=data;
    }
    else{
        link* curr=virus_list;
        while(curr->nextVirus!=NULL)
            curr=curr->nextVirus;
        curr->nextVirus=malloc(sizeof(link));
        curr->nextVirus->nextVirus=NULL;
        curr->nextVirus->vir=data;
    }
    return virus_list;
}

/*  Free the memory allocated by the list. */
void list_free(link *virus_list) {
    link* tmp;
    while (virus_list != NULL){
        tmp=virus_list;
        virus_list = virus_list->nextVirus;
        free(tmp->vir->sig);
        free(tmp->vir);
        free(tmp);
    }
}
/*  This function returns the size of the list. */
int list_size(link *virus_list) {
    link* tmp=virus_list ;
    int counter=0;
    while (tmp != NULL){
        counter++;
        tmp = tmp->nextVirus;
    }
    return counter;
}

 /* This function returns the link in index location at the list. */
link* link_by_index(link *virus_list, int index){
    link* tmp=virus_list;
    while(index>0){
        tmp=tmp->nextVirus;
        index--;}
    return tmp;
}

/*  Loads signatures of viruses from a file into the list. */
void loadSignatures(link** virus_list_pointer){
    printf("please enter a signature file name\n");
    char fileName[256];
    fgets(fileName,256,stdin);
    sscanf(fileName,"%s",fileName);
    FILE *stream = fopen(fileName, "r");
    for (int i = 0; i < 3; i++)
        fgetc(stream);
    endian=fgetc(stream);
    virus *v = readVirus(stream);
    while (v != NULL) {
        if (!feof(stream))
            *virus_list_pointer=list_append(*virus_list_pointer, v);
        else{
            free(v->sig);
                free(v);
        }
        v = readVirus(stream);
    }
    fclose(stream);       
}

void printSignatures (link** virus_list_pointer){
    list_print(*virus_list_pointer, stdout);
}

/*  Compares the content of the buffer byte-by-byte
    with the virus signatures stored in the virus_list linked list.
    If a virus is detected, it prints its details. */
void detect_virus(char *buffer, unsigned int size, link *virus_list, FILE* output){
    bool found=false;
    for (int i=0; i<list_size(virus_list); i++){
        virus *v=NULL;
        v=link_by_index(virus_list,i)->vir;
        for (int j=0; j<size && (size-j>=v->SigSize); j++){
            if (memcmp((void*)buffer+j,v->sig,v->SigSize)==0){
                fprintf(output,"The starting byte location in the suspected file: %d\n",j);
                fprintf(output,"Virus name: %s\n",v->virusName);
                fprintf(output,"Virus size: %d\n",v->SigSize);
                found=true;
            }
        }
    }
    if(!found)
        fprintf(output, "no viruses \n");
}

void detectViruses(link** virus_list_pointer,char *argv1){
    FILE *srteam2=fopen(argv1,"r");    
    fseek(srteam2, 0L, SEEK_END);
    long sz = ftell(srteam2);
    fseek(srteam2, 0L, SEEK_SET);
    
    char *buffer=malloc(10000);
    fread(buffer,1,sz,srteam2);//puts what in the srteam2 into the ptr(in the memory), sz elements, each one 1 byte(char)
    unsigned int size=0;
    if (sz<1000)
        size=sz;
    else
        size=1000;
    detect_virus(buffer,size,*virus_list_pointer, stdout);
    fclose(srteam2);
    free(buffer);           
}

/*  This function recieves the starting byte location in the suspected file 
    and the size of the virus signature. It cancels its effect by replacing
    all virus code by NOP instructions. */
void kill_virus(char *fileName, int signitureOffset, int signitureSize){
    FILE* file=fopen(fileName,"r+");
    fseek(file,signitureOffset,SEEK_SET);
    char *ptr=malloc(signitureSize);
    for(int i=0; i<signitureSize; i++)
        ptr[i]=0x90;
    fwrite(ptr,1,signitureSize,file);
    fclose(file);
    free(ptr);
}

void fixFile(link** virus_list_pointer,char *argv1){
    printf("please enter  the starting byte location in the suspected file and the size of the virus signature: \n");
    char startingByte[5];
    fgets(startingByte,5,stdin);
    int signitureOffset;
    sscanf(startingByte,"%d",&signitureOffset);
    __fpurge(stdin);
    char size[5];
    fgets(size,5,stdin);
    int signitureSize;
    sscanf(size,"%d",&signitureSize);
    __fpurge(stdin);

    kill_virus(argv1,  signitureOffset,  signitureSize);
}










