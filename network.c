#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <dirent.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <openssl/md5.h>
#include <openssl/hmac.h>
#include <netdb.h>
#include <fcntl.h>
#include <sys/wait.h>

#define Max_Packet_Length 10240

struct print_data{
    char filename[100]; //filename
    off_t size; //size
    time_t mtime; //last modified
    char type; //filetype
}pdata[1024];

struct print_hash{
    char *filename; //filename
    unsigned char hash[MD5_DIGEST_LENGTH]; //hash
    time_t mtime; //last modified
}hdata[1024];

int isudpset = 0, error = -1, i = 0;
char response[Max_Packet_Length];
char fileDownloadName[1024];

int handleCheckAll()
{
    unsigned char c[MD5_DIGEST_LENGTH];
    DIR *dp;
    i = 0;
    int a;
    struct dirent *ep;
    dp = opendir ("./");
    struct stat fileStat;

    if (dp != NULL)
    {
        while (ep = readdir (dp))
        {
            if(stat(ep->d_name,&fileStat) < 0)
                return 1;
            else
            {
                char *filename=ep->d_name;
                hdata[i].filename = ep->d_name;
                hdata[i].mtime = fileStat.st_mtime;
                FILE *inFile = fopen (filename, "r");
                int bytes;
                unsigned char data[1024];
                MD5_CTX mdContext;

                if(inFile == NULL){
                	error = 1;
                	sprintf(response, "%s can't be opeed.", filename);
                	return ;
                }
                MD5_Init(&mdContext);
                while(bytes = fread(data, 1, 1024, inFile) != 0)
                	MD5_Update(&mdContext, data, bytes);
                MD5_Final(c, &mdContext);
                for(a = 0; a < MD5_DIGEST_LENGTH; a++){
                	hdata[i].hash[a] = c[a];
                }
                fclose(inFile);
                i++;
            }
        }
    }
    else
    {
        error = 1;
        sprintf(response,"Couldn't open the directory");
    }
}

int handleVerify(char *file)
{
    unsigned char c[MD5_DIGEST_LENGTH];
    DIR *dp;
    i = 0;
    int a, flag = 0;
    struct dirent *ep;
    dp = opendir ("./");
    struct stat fileStat;

    if (dp != NULL)
    {
        while (ep = readdir (dp))
        {
            if(stat(ep->d_name,&fileStat) < 0)
                return 1;
            else if(strcmp(file,ep->d_name) == 0)
            {
            	flag = 1;
                char *filename=ep->d_name;
                hdata[i].filename = ep->d_name;
                hdata[i].mtime = fileStat.st_mtime;
                FILE *inFile = fopen (filename, "r");
                MD5_CTX mdContext;
                int bytes;
                unsigned char data[1024];

                if (inFile == NULL) {
                    error = 1;
                    sprintf(response,"%s can't be opened.", filename);
                    return 0;
                }

                MD5_Init (&mdContext);
                while ((bytes = fread (data, 1, 1024, inFile)) != 0)
                    MD5_Update (&mdContext, data, bytes);
                MD5_Final (c,&mdContext);
                for(a = 0; a < MD5_DIGEST_LENGTH; a++)
                    hdata[i].hash[a] = c[a];
                fclose (inFile);
                i++;
                break;
            }
            else
                continue;
        }
        if(flag == 0){
        	error = 1;
            sprintf(response,"File not found.");
            return 0;
        }
    }
    else
    {
        error = 1;
        sprintf(response,"Couldn't open the directory");
    }
}

void FileHash_handler(char *request)
{
    memset(response, 0, sizeof(response));
    char *request_data = NULL;
    char delim[] = " \n";
    request_data = strtok(request,delim);
    request_data = strtok(NULL,delim);
    if(request_data == NULL)
    {
        error = 1;
        sprintf(response,"ERROR: Wrong Format");
    }
    while(request_data != NULL)
    {
        if(strcmp(request_data,"CheckAll") == 0)
        {
            request_data = strtok(NULL,delim);

            if(request_data != NULL)
            {
                error = 1;
                sprintf(response,"ERROR: Wrong Format. The correct format is:\nFileHash CheckAll");
                return;
            }
            else
            {
                handleCheckAll();
            }

        }
        else if(strcmp(request_data,"Verify") == 0)
        {
            request_data = strtok(NULL,delim);
            if(request_data == NULL)
            {
                error = 1;
                sprintf(response,"ERROR: Wrong Format. The correct format is:\nFileHash Verify <filename>");
                return;
            }
            char *filename = request_data;
            request_data = strtok(NULL,delim);
            if(request_data != NULL)
            {
                error = 1;
                sprintf(response,"ERROR: Wrong Format. The correct format is:\nFileHash Verify <filename>");
                return;
            }
            else
                handleVerify(filename);
        }
    }
}

int handleLongList()
{
    DIR *dp;
    i = 0; 
    struct dirent *ep;
    dp = opendir ("./");
    struct stat fileStat;

    if (dp != NULL)
    {
        while (ep = readdir (dp))
        {
            if(stat(ep->d_name,&fileStat) < 0)
                return 1;
            else
            {
                strcpy(pdata[i].filename, ep->d_name);
                pdata[i].size = fileStat.st_size;
                pdata[i].mtime = fileStat.st_mtime;
                pdata[i].type = (S_ISDIR(fileStat.st_mode)) ? 'd' : '-';
                i++;
            }
        }
        closedir (dp);
    }
    else
    {
    	error = 1;
        sprintf(response, "Couldn't open the directory");
    }
}

int handleShortList(time_t start_time,time_t end_time)
{
    DIR *dp;
    i = 0;
    struct dirent *ep;
    dp = opendir ("./");
    struct stat fileStat;

    if (dp != NULL)
    {
        while (ep = readdir (dp))
        {
            if(stat(ep->d_name,&fileStat) < 0)
                return 1;
            else if(difftime(fileStat.st_mtime,start_time) > 0 && difftime(end_time,fileStat.st_mtime) > 0)
            {
                strcpy(pdata[i].filename , ep->d_name);
                pdata[i].size = fileStat.st_size;
                pdata[i].mtime = fileStat.st_mtime;
                pdata[i].type = (S_ISDIR(fileStat.st_mode)) ? 'd' : '-';
                i++;
            }
        }
        closedir (dp);
    }
    else
    {
        error = 1;
        sprintf(response,"Couldn't open the directory");
    }
}

void IndexGet_handler(char *request)
{
    memset(response, 0, sizeof(response));
    char *request_data = NULL;
    char delim[] = " \n";
    struct tm tm;
    time_t start_time , end_time;
    int enter = 1;
    char *regexp;

    request_data = strtok(request,delim);
    request_data = strtok(NULL,delim);
    if(request_data == NULL)
    {
        error = 1;
        sprintf(response,"ERROR: Wrong Format.\n Correct Formats : (1)IndexGet<space>LongList\n(2)IndexGet<space>ShortList<space>StartTimeStamp<space>EndTimeStamp");
        return;
    }
    else
    {
        if(strcmp(request_data,"LongList") == 0)
        {
            request_data = strtok(NULL,delim);

            if(request_data != NULL)
            {
                error = 1;
                sprintf(response,"ERROR: Wrong Format. The correct format is:\nIndexGet LongList");
                return;
            }
            else
            {
                handleLongList();
            }
        }
        else if(strcmp(request_data,"ShortList") == 0)
        {
            request_data = strtok(NULL,delim);
            if(request_data == NULL)
            {
                error = 1;
                sprintf(response,"ERROR: Wrong Format. The correct format is:\nIndexGet ShortList <timestamp1> <timestamp2>");
                return;
            }
            while(request_data != NULL)
            {
                if(enter >= 3)
                {
                    error = 1;
                    sprintf(response,"ERROR: Wrong Format. The correct format is:\nIndexGet ShortList <timestamp1> <timestamp2>");
                    return;
                }
                if (strptime(request_data, "%d-%b-%Y-%H:%M:%S", &tm) == NULL)
                {
                    error = 1;
                    sprintf(response,"ERROR: Wrong Format. The correct format is:\nDate-Month-Year-hrs:min:sec");
                    return;
                }
                if(enter == 1)
                    start_time = mktime(&tm);
                else
                    end_time = mktime(&tm);
                enter++;
                request_data = strtok(NULL,delim);
            }
            handleShortList(start_time,end_time);
        }
     /* else if(strcmp(request_data,"RegEx") == 0)
        {
            request_data = strtok(NULL,delim);
            if(request_data == NULL)
            {
                printf("ERROR: Wrong Format. The correct format is:\nIndexGet RegEx <regular expression>\n");
                _exit(1);
            }
            regexp = request_data;
            request_data = strtok(NULL,delim);
            if(request_data != NULL)
            {
                printf("ERROR: Wrong Format. The correct format is:\nIndexGet RegEx <regular expression>\n");
                _exit(1);
            }
            handleRegEx(regexp);
        }
      */  else
        {
            error = 1;
            sprintf(response,"ERROR: Wrong Format.\n");
            return;
        }
    }
}

int parse_request(char *request)
{
    char copyrequest[100];
    strcpy(copyrequest,request);
    char *request_data = NULL;
    const char delim[] = " \n";
    request_data = strtok(copyrequest,delim);
    if(request_data != NULL)
    {   
        if(strcmp(request_data,"IndexGet") == 0)
            return 1;
        else if(strcmp(request_data,"FileHash") == 0)
            return 2;
        else if(strcmp(request_data,"FileDownload") == 0)
            return 3;
        else if(strcmp(request_data,"FileUpload") == 0)
            return 4;
        else if(strcmp(request_data, "Quit") == 0 || strcmp(request_data, "Q") == 0 || strcmp(request_data, "quit") == 0 || strcmp(request_data, "q") == 0 || strcmp(request_data, "exit") == 0 || strcmp(request_data, "Exit") == 0)
            return 5;
        else
            return -1;
    }
}

void FileDownload_handler(char *request)
{
	memset(response, 0, sizeof(response));
    char *request_data = NULL;
    char delim[] = " \n";
    request_data = strtok(request,delim);
    request_data = strtok(NULL,delim);
    if(request_data == NULL)
    {
        error = 1;
        sprintf(response,"ERROR: Wrong Format. The correct format is:\nFileDownload <file_name>\n");
        return;
    }
    strcpy(fileDownloadName,request_data);
    request_data = strtok(NULL,delim);
    if(request_data != NULL)
    {
        error = 1;
        sprintf(response,"ERROR: Wrong Format. The correct format is:\nFileDownload <file_name>\n");
        return;
    }
}

int tcp_server(char *listenportno)
{
	int listenfd = 0, connfd = 0;
	struct sockaddr_in serv_addr;
	int portno = atoi(listenportno);

	char readBuff[1024], writeBuff[1024];
	time_t ticks;

	listenfd = socket(AF_INET, SOCK_STREAM, 0);
	if(listenfd == -1){
		perror("Unable to create socket");
	    exit(0);
	}

	memset(&serv_addr, 0, sizeof(serv_addr));
    memset(readBuff, 0, sizeof(readBuff)); 
    memset(writeBuff, 0, sizeof(writeBuff)); 

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(portno);

    if(bind(listenfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) == -1){
    	perror("Unable to bind");
	    exit(0);
    }

    listen(listenfd, 10); // max 10 connections at a time;
    connfd = accept(listenfd, (struct sockaddr*)NULL, NULL);

    int n;
    n = read(connfd, readBuff, sizeof(readBuff));

    while(n > 0)
    {
    	size_t size = strlen(readBuff) + 1;
    	char *request = malloc(size);
    	strcpy(request, readBuff);
    	printf("%s", request);
    	printf("$ ");
    	fflush(stdout);
    	int type_of_request = parse_request(request);
    	memset(response, 0, sizeof(response));
    	if(type_of_request == -1){
    		error = 1;
    		strcpy(response, "Error: No request of this type.\n");
    	}
    	else if(type_of_request == 1){
    		IndexGet_handler(request);
    	}
    	else if(type_of_request == 2){
    		FileHash_handler(request);
    	}
    	else if(type_of_request == 3){
    		FileDownload_handler(request);
    	}
    	if(error == 1){
            memset(writeBuff, 0, strlen(writeBuff));
    		strcpy(writeBuff, response);
    		strcat(writeBuff,"~@~");
            write(connfd , writeBuff , strlen(writeBuff));
            error = -1;
    		memset(response, 0, sizeof(response)); 
            memset(writeBuff, 0, strlen(writeBuff));
            memset(readBuff, 0, sizeof(readBuff)); 
            while((n = read(connfd, readBuff, sizeof(readBuff)))<=0);
            continue;
    	}
    	else if(type_of_request == 1){
    		int a;
    		memset(response, 0, sizeof(response));
            memset(writeBuff, 0, strlen(writeBuff));
    		for(a = 0 ; a < i ; a++)
            {
                sprintf(response, "%-35s| %-10d| %-3c| %-20s" , pdata[a].filename , pdata[a].size , pdata[a].type , ctime(&pdata[a].mtime));
                strcat(writeBuff,response);
            }
            strcat(writeBuff,"~@~");
    		write(connfd, writeBuff, strlen(writeBuff));
    	}
    	else if(type_of_request == 2){
    		int a;
            for (a = 0 ; a < i ; a++)
            {
            	memset(response, 0, sizeof(response));
            	memset(writeBuff, 0, strlen(writeBuff));
                sprintf(response, "%-35s |   ", hdata[a].filename);

                strcat(writeBuff,response);
                int c;
    			memset(response, 0, sizeof(response));

                for (c = 0 ; c < MD5_DIGEST_LENGTH ; c++)
                {
                    sprintf(response, "%x",hdata[a].hash[c]);
                    strcat(writeBuff,response);
                }
                sprintf(response, "\t %20s",ctime(&hdata[a].mtime));
                strcat(writeBuff,response);
            	write(connfd , writeBuff , strlen(writeBuff));
            }
            memset(writeBuff, 0, strlen(writeBuff));
            strcpy(writeBuff,"~@~");
            write(connfd , writeBuff , strlen(writeBuff));
    	}
    	else if(type_of_request == 3)
        {
            FILE* fp;
            fp = fopen(fileDownloadName,"rb");
            size_t bytes_read;
			memset(response, 0, sizeof(response));
            while(!feof(fp))
            {
                bytes_read = fread(response, 1, 1024, fp);
                memcpy(writeBuff,response,bytes_read);
                write(connfd , writeBuff , bytes_read);
                memset(writeBuff, 0, sizeof(writeBuff));
                memset(response, 0, sizeof(response));
            }
            memcpy(writeBuff,"~@~",3);
            write(connfd , writeBuff , 3);
            memset(writeBuff, 0, sizeof(writeBuff));
            fclose(fp);
        }
    	else if(type_of_request == 4){
    		char ch = 'y';
        	memset(writeBuff, 0, sizeof(writeBuff));
    		if(ch == 'n'){
        		strcpy(writeBuff, "FileUpload Deny");
    		}
    		else {
				strcpy(writeBuff, "FileUpload Accept");
				write(connfd, writeBuff, strlen(writeBuff));

				char *request_data = strtok(request, " \n");
				request_data = strtok(NULL, " \n");
				int f = open(request_data, O_WRONLY | O_CREAT | O_EXCL, (mode_t)0600);
				if(f == -1){
					perror("Error opening file for writing\n");
					return 1;
				}   
				close(f);
				FILE *fp = fopen(request_data, "wb");
				
				n = read(connfd, readBuff, sizeof(readBuff)-1);
		        while(1)
		        {
		            readBuff[n] = 0;
		            if(readBuff[n-1] == '~' && readBuff[n-3] == '~' && readBuff[n-2] == '@')
		            {
		                readBuff[n-3] = 0;
		                fwrite(readBuff,1,n-3,fp);
		                fclose(fp);
		                memset(readBuff, 0,n-3);
		                break;
		            }
		            else
		            {
		                fwrite(readBuff,1,n,fp);
		                memset(readBuff, 0,n);
		            }
		            n = read(connfd, readBuff, sizeof(readBuff)-1);
		            if(n < 0)
		                break;
		        }
    		}
    	}

        memset(writeBuff, 0, sizeof(writeBuff));
    	memset(readBuff, 0, sizeof(readBuff));
 		while((n = read(connfd, readBuff, sizeof(readBuff)))<=0);
    }
    close(connfd);
    wait(NULL);
}

int tcp_client(char *ip, char *connectportno)
{
	int sockfd = 0, n = 0, filedownload;
    char readBuff[1024], writeBuff[1024];
    struct sockaddr_in serv_addr;
    int portno = atoi(connectportno);
    char DownloadName[1024];
    char UploadName[1024];
    char request[1024];
    memset(readBuff, 0,sizeof(readBuff));
    memset(&serv_addr, 0, sizeof(serv_addr)); 
    memset(writeBuff, 0,sizeof(writeBuff));
  
    if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        printf("\n Error : Could not create socket \n");
        return 1;
    } 

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(portno); 
    serv_addr.sin_addr.s_addr = inet_addr(ip);

    while(connect(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0);

    while(1)
    {
    	printf("$ ");
    	memset(writeBuff, 0, sizeof(writeBuff));
    	memset(request, 0, sizeof(request));
    	fgets(writeBuff, sizeof(writeBuff), stdin);
    	strcpy(request, writeBuff);
    	char *cresponse = malloc(Max_Packet_Length);
    	char *filename = strtok(request, " \n");
    	FILE *fp = NULL;
    	if(strcmp(filename,"quit") == 0)
			break;
    	if(strcmp(filename, "FileUpload") == 0){
    		filename = strtok(NULL," \n");
            strcpy(UploadName,filename);
 	 	}
 	 	if(strcmp(filename,"FileDownload") == 0)
        {
            filedownload = 1;
            filename = strtok(NULL," \n");
            strcpy(DownloadName,filename);
            fp = fopen(DownloadName,"wb");
        }
    	write(sockfd, writeBuff, strlen(writeBuff));

    	memset(readBuff, 0, sizeof(readBuff));
    	n = read(sockfd, readBuff, sizeof(readBuff)-1);
    	
    	if(strcmp(readBuff, "FileUpload Accept") == 0)
    	{
    		printf("Upload Accepted\n");
            memset(writeBuff, 0, sizeof(writeBuff));
    		size_t bytes_read;
            FILE *fp = fopen(UploadName, "rb");
            while(!feof(fp))
            {
            	bytes_read = fread(cresponse, 1, 1024, fp);
                cresponse[1024] = 0;
                memcpy(writeBuff,cresponse,bytes_read);
                write(sockfd , writeBuff , bytes_read);
                memset(writeBuff, 0, sizeof(writeBuff));
                memset(cresponse, 0, sizeof(cresponse));
            }
            memcpy(writeBuff,"~@~",3);
            write(sockfd , writeBuff , 3);
            memset(writeBuff, 0, sizeof(writeBuff));
            memset(readBuff, 0, strlen(readBuff));
            fclose(fp);
    	}
    	else 
    	{
    		memset(cresponse, 0, sizeof(cresponse));
            while(1)
            {
                readBuff[n] = 0;
                if(readBuff[n-1] == '~' && readBuff[n-3] == '~' && readBuff[n-2] == '@')
                {
                    readBuff[n-3] = 0;
                    if(filedownload == 1)
                    {
                        fwrite(readBuff,1,n-3,fp);
                        fclose(fp);
                    }
                    else
                    	strcat(cresponse,readBuff);
                    memset(readBuff, 0,strlen(readBuff));
                    break;
                }
                else
                { 
                	if(filedownload == 1)
                        fwrite(readBuff,1,n,fp);
                    else
                    	strcat(cresponse,readBuff);
                    memset(readBuff, 0,strlen(readBuff));
                }
                n = read(sockfd, readBuff, sizeof(readBuff)-1);
                if(n < 0)
                    break;
            }
            if(filedownload == 0)
	            printf("%s\n",cresponse);
    	    else {
            	filedownload = 1;
        	    printf("File Downloaded\n");
    	    }
    	}
    }
    return 0;
}

int udp_server(char *listenportno)
{
	int listenfd = 0;
	struct sockaddr_in serv_addr;
	int portno = atoi(listenportno);

	char readBuff[1024], writeBuff[1024];
	time_t ticks;

	listenfd = socket(AF_INET, SOCK_STREAM, 0);
	if(listenfd == -1){
		perror("Unable to create socket");
	    exit(0);
	}

	memset(&serv_addr, 0, sizeof(serv_addr));
    memset(readBuff, 0, sizeof(readBuff)); 
    memset(writeBuff, 0, sizeof(writeBuff));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(portno);

    bind(listenfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr));

    int n;
    n = read(listenfd, readBuff, sizeof(readBuff));

    while(n > 0)
    {
    	size_t size = strlen(readBuff) + 1;
    	char *request = malloc(size);
    	strcpy(request, readBuff);
    	printf("%s", request);
    	printf("$ ");
    	fflush(stdout);
    	int type_of_request = parse_request(request);
    	memset(response, 0, sizeof(response));
    	if(type_of_request == -1){
    		error = 1;
    		strcpy(response, "Error: No request of this type.\n");
    	}
    	else if(type_of_request == 1){
    		IndexGet_handler(request);
    	}
    	else if(type_of_request == 2){
    		FileHash_handler(request);
    	}
    	else if(type_of_request == 3){
    		FileDownload_handler(request);
    	}
    	if(error == 1){
            memset(writeBuff, 0, strlen(writeBuff));
    		strcpy(writeBuff, response);
    		strcat(writeBuff,"~@~");
            write(listenfd , writeBuff , strlen(writeBuff));
            error = -1;
    		memset(response, 0, sizeof(response)); 
            memset(writeBuff, 0, strlen(writeBuff));
            memset(readBuff, 0, sizeof(readBuff)); 
            while((n = read(listenfd, readBuff, sizeof(readBuff)))<=0);
            continue;
    	}
    	else if(type_of_request == 1){
    		int a;
    		memset(response, 0, sizeof(response));
            memset(writeBuff, 0, strlen(writeBuff));
    		for(a = 0 ; a < i ; a++)
            {
                sprintf(response, "%-35s| %-10d| %-3c| %-20s" , pdata[a].filename , pdata[a].size , pdata[a].type , ctime(&pdata[a].mtime));
                strcat(writeBuff,response);
            }
            strcat(writeBuff,"~@~");
    		write(listenfd, writeBuff, strlen(writeBuff));
    	}
    	else if(type_of_request == 2){
    		int a;
            for (a = 0 ; a < i ; a++)
            {
            	memset(response, 0, sizeof(response));
            	memset(writeBuff, 0, strlen(writeBuff));
                sprintf(response, "%-35s |   ", hdata[a].filename);

                strcat(writeBuff,response);
                int c;
    			memset(response, 0, sizeof(response));

                for (c = 0 ; c < MD5_DIGEST_LENGTH ; c++)
                {
                    sprintf(response, "%x",hdata[a].hash[c]);
                    strcat(writeBuff,response);
                }
                sprintf(response, "\t %20s",ctime(&hdata[a].mtime));
                strcat(writeBuff,response);
            	write(listenfd , writeBuff , strlen(writeBuff));
            }
            memset(writeBuff, 0, strlen(writeBuff));
            strcpy(writeBuff,"~@~");
            write(listenfd, writeBuff , strlen(writeBuff));
    	}
    	else if(type_of_request == 3)
        {
            FILE* fp;
            fp = fopen(fileDownloadName,"rb");
            size_t bytes_read;
			memset(response, 0, sizeof(response));
            while(!feof(fp))
            {
                bytes_read = fread(response, 1, 1024, fp);
                memcpy(writeBuff,response,bytes_read);
                write(listenfd, writeBuff , bytes_read);
                memset(writeBuff, 0, sizeof(writeBuff));
                memset(response, 0, sizeof(response));
            }
            memcpy(writeBuff,"~@~",3);
            write(listenfd, writeBuff , 3);
            memset(writeBuff, 0, sizeof(writeBuff));
            fclose(fp);
        }
    	else if(type_of_request == 4){
    		char ch = 'y';
        	memset(writeBuff, 0, sizeof(writeBuff));
    		if(ch == 'n'){
        		strcpy(writeBuff, "FileUpload Deny");
    		}
    		else {
				strcpy(writeBuff, "FileUpload Accept");
				write(listenfd, writeBuff, strlen(writeBuff));

				char *request_data = strtok(request, " \n");
				request_data = strtok(NULL, " \n");
				int f = open(request_data, O_WRONLY | O_CREAT | O_EXCL, (mode_t)0600);
				if(f == -1){
					perror("Error opening file for writing\n");
					return 1;
				}   
				close(f);
				FILE *fp = fopen(request_data, "wb");
				
				n = read(listenfd, readBuff, sizeof(readBuff)-1);
		        while(1)
		        {
		            readBuff[n] = 0;
		            if(readBuff[n-1] == '~' && readBuff[n-3] == '~' && readBuff[n-2] == '@')
		            {
		                readBuff[n-3] = 0;
		                fwrite(readBuff,1,n-3,fp);
		                fclose(fp);
		                memset(readBuff, 0,n-3);
		                break;
		            }
		            else
		            {
		                fwrite(readBuff,1,n,fp);
		                memset(readBuff, 0,n);
		            }
		            n = read(listenfd, readBuff, sizeof(readBuff)-1);
		            if(n < 0)
		                break;
		        }
    		}
    	}

        memset(writeBuff, 0, sizeof(writeBuff));
    	memset(readBuff, 0, sizeof(readBuff));
 		while((n = read(listenfd, readBuff, sizeof(readBuff)))<=0);
    }
    close(listenfd);
    wait(NULL);
}

int udp_client(char *ip, char *connectportno)
{
	int sockfd = 0, n = 0, filedownload;
    char readBuff[1024], writeBuff[1024];
    struct sockaddr_in serv_addr;
    int portno = atoi(connectportno);
    char DownloadName[1024];
    char UploadName[1024];
    char request[1024];
    memset(readBuff, 0,sizeof(readBuff));
    memset(&serv_addr, 0, sizeof(serv_addr)); 
    memset(writeBuff, 0,sizeof(writeBuff));
  
    if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        printf("\n Error : Could not create socket \n");
        return 1;
    } 

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(portno); 
    serv_addr.sin_addr.s_addr = inet_addr(ip);

  //  while(connect(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0);

    while(1)
    {
    	printf("$ ");
    	memset(writeBuff, 0, sizeof(writeBuff));
    	memset(request, 0, sizeof(request));
    	fgets(writeBuff, sizeof(writeBuff), stdin);
    	strcpy(request, writeBuff);
    	char *cresponse = malloc(Max_Packet_Length);
    	char *filename = strtok(request, " \n");
    	FILE *fp = NULL;
    	if(strcmp(filename,"quit") == 0)
			break;
    	if(strcmp(filename, "FileUpload") == 0){
    		filename = strtok(NULL," \n");
            strcpy(UploadName,filename);
 	 	}
 	 	if(strcmp(filename,"FileDownload") == 0)
        {
            filedownload = 1;
            filename = strtok(NULL," \n");
            strcpy(DownloadName,filename);
            fp = fopen(DownloadName,"wb");
        }
    	write(sockfd, writeBuff, strlen(writeBuff));

    	memset(readBuff, 0, sizeof(readBuff));
    	n = read(sockfd, readBuff, sizeof(readBuff)-1);
    	
    	if(strcmp(readBuff, "FileUpload Accept") == 0)
    	{
    		printf("Upload Accepted\n");
            memset(writeBuff, 0, sizeof(writeBuff));
    		size_t bytes_read;
            FILE *fp = fopen(UploadName, "rb");
            while(!feof(fp))
            {
            	bytes_read = fread(cresponse, 1, 1024, fp);
                cresponse[1024] = 0;
                memcpy(writeBuff,cresponse,bytes_read);
                write(sockfd , writeBuff , bytes_read);
                memset(writeBuff, 0, sizeof(writeBuff));
                memset(cresponse, 0, sizeof(cresponse));
            }
            memcpy(writeBuff,"~@~",3);
            write(sockfd , writeBuff , 3);
            memset(writeBuff, 0, sizeof(writeBuff));
            memset(readBuff, 0, strlen(readBuff));
            fclose(fp);
    	}
    	else 
    	{
    		memset(cresponse, 0, sizeof(cresponse));
            while(1)
            {
                readBuff[n] = 0;
                if(readBuff[n-1] == '~' && readBuff[n-3] == '~' && readBuff[n-2] == '@')
                {
                    readBuff[n-3] = 0;
                    if(filedownload == 1)
                    {
                        fwrite(readBuff,1,n-3,fp);
                        fclose(fp);
                    }
                    else
                    	strcat(cresponse,readBuff);
                    memset(readBuff, 0,strlen(readBuff));
                    break;
                }
                else
                { 
                	if(filedownload == 1)
                        fwrite(readBuff,1,n,fp);
                    else
                    	strcat(cresponse,readBuff);
                    memset(readBuff, 0,strlen(readBuff));
                }
                n = read(sockfd, readBuff, sizeof(readBuff)-1);
                if(n < 0)
                    break;
            }
            if(filedownload == 0)
	            printf("%s\n",cresponse);
    	    else {
            	filedownload = 1;
        	    printf("File Downloaded\n");
    	    }
    	}
    }
    return 0;
}

int main(int argc,char *argv[])
{
    if(argc != 5)
    {
		printf("Incorrect format\n");
        printf("\n Usage: %s <listenportno> <ip of server> <connectportno> <protocol>\n",argv[0]);
        return 1;
    } 
    char *listenportno = argv[1];
    char *connectportno = argv[3];
    char *ip = argv[2];
    if(strcmp(argv[3],"udp")==0)
		isudpset = 1;
    else
	 	isudpset = 0;
    pid_t pid;
    pid = fork();
    if(pid == 0)
    {
		if(isudpset)
			udp_server(listenportno);
		else
    	    tcp_server(listenportno);
    }
    else if(pid > 0)
    {        
		if(isudpset)
			udp_client(ip,connectportno);
		else
        	tcp_client(ip,connectportno);
    }
    return 0;
}
