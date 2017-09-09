/***************************************************************************
 *   Copyright (C) 2004 by l4t3n8                                          *
 *   mailbockx@freenet.de                                                  *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.             *
 ***************************************************************************/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "readpe.h"

#define LINE "--------------------------------------------------------------------------------"

//-----------------------------------------------------------------------------
int main(int argc, char *argv[])
{
	if(argc < 2) 
	{
		cout << "USAGE: readpe [FILENAME] [-i]" << endl;
		return 0;
	}		
		 
	char *file, *name, filename[256], buf[256];	
	strcpy(filename,argv[1]);	
	
	ifstream* in = new ifstream(filename,ios::binary|ios::in);	
	
	if(*in)
	{	
		// REMEMBER FILESIZE FOR LATER PURPOSES

		in->seekg(0,ios::end);
		unsigned int fsize = in->tellg();				
		
		// READ FILE TO MEMORY
		in->seekg(0,ios::beg);
		file = new char[fsize];
		in->read(file,fsize);							
		in->close();	delete in;		
			
		printf("%s\nFILE: %s\nSIZE: %0.2f KB\n%s\n",LINE,filename,(float)fsize/1024.0f,LINE);										
		
		IMAGE_DOS_HEADER* dos_hdr	= (IMAGE_DOS_HEADER*)file;
		IMAGE_NT_HEADERS32* pe_hdr	= (IMAGE_NT_HEADERS32*)(file+dos_hdr->e_lfanew);				
		
		if(dos_hdr->e_magic == IMAGE_DOS_SIGNATURE)		
		{						
			printf("PE OFFSET\t: 0x%08X\tSIGNATURE\t: 0x%08x\n",dos_hdr->e_lfanew,pe_hdr->Signature);			
			
			// TRY TO FIND THE PE HEADER
			
			if(pe_hdr->Signature == IMAGE_NT_SIGNATURE)
			{
				// PARSE SOME HEADER INFORMATION
				printf("IMAGEBASE\t: 0x%08X\tIMAGESIZE\t: 0x%08X\n",pe_hdr->OptionalHeader.ImageBase,pe_hdr->OptionalHeader.SizeOfImage);
				printf("ENTRYPOINT\t: 0x%08X\n",pe_hdr->OptionalHeader.AddressOfEntryPoint);								
				printf("\nSECTION NAME\tRAW SIZE\tRAW OFFSET\tVIRTUAL SIZE\tVIRTUAL OFFSET\n%s\n",LINE);																		
				
				// PARSE SECTIONS
				bool has_export = false;
				IMAGE_SECTION_HEADER* s_hdr = (IMAGE_SECTION_HEADER*)((char*)pe_hdr+sizeof(IMAGE_NT_HEADERS32));
				for(unsigned int i=0; i<pe_hdr->FileHeader.NumberOfSections; i++,s_hdr++)
					printf(	"%10s\t0x%08X\t0x%08X\t0x%08X\t0x%08X\n",s_hdr->Name,s_hdr->SizeOfRawData,s_hdr->PointerToRawData,s_hdr->Misc.VirtualSize,s_hdr->VirtualAddress);										

				// PARSE DATA DIRECTORYS
				DWORD eat_addr;
				IMAGE_EXPORT_DIRECTORY*  img_eat;
				IMAGE_IMPORT_DESCRIPTOR* img_iat;
								
				printf("%s\n<DATA DIRECTORYS>\n%s\nVA\t\tSIZE\t\tTYP\n",LINE,LINE);
				for(unsigned int i=0; i<IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++)
				{
					char d_name[256];
					switch(i)
					{
						case 0:	 
							strcpy(d_name,"Export Directory"); 
							eat_addr   = pe_hdr->OptionalHeader.DataDirectory[i].VirtualAddress;
							img_eat    = (IMAGE_EXPORT_DIRECTORY*)(file+pe_hdr->OptionalHeader.DataDirectory[i].VirtualAddress);							
							has_export = pe_hdr->OptionalHeader.DataDirectory[i].Size == 0 ? false : true;
							break;
						case 1:	 						
							strcpy(d_name,"Import Directory"); 							
							img_iat  = (IMAGE_IMPORT_DESCRIPTOR*)(file+pe_hdr->OptionalHeader.DataDirectory[i].VirtualAddress);
							break;
						case 2:	 strcpy(d_name,"Resource Directory"); break;
						case 3:	 strcpy(d_name,"Exception Directory"); break;
						case 4:	 strcpy(d_name,"Security Directory"); break;							
						case 5:	 strcpy(d_name,"Base Relocation Table"); break;
						case 6:	 strcpy(d_name,"Debug Directory"); break;
						case 7:	 strcpy(d_name,"Architecture Specific Data"); break;
						case 8:	 strcpy(d_name,"RVA of GP"); break;
						case 9:	 strcpy(d_name,"TLS Directory"); break;
						case 10: strcpy(d_name,"Load Configuration Directory"); break;
						case 11: strcpy(d_name,"Bound Import Directory"); break;
						case 12: strcpy(d_name,"Import Address Table"); break;
						case 13: strcpy(d_name,"Delay Load Import Descriptors"); break;
						case 14: strcpy(d_name,"COM Runtime descriptor"); break;
						case 15: strcpy(d_name,"UNKNOWN"); break;			
						default: strcpy(d_name,"UNKNOWN"); break;
					};
					if(pe_hdr->OptionalHeader.DataDirectory[i].Size != 0)
						printf("0x%08X\t0x%08X\t%s\n",pe_hdr->OptionalHeader.DataDirectory[i].VirtualAddress,pe_hdr->OptionalHeader.DataDirectory[i].Size,d_name);					
				}																				
				// PARSE EXPORT ADDRESS TABLE ( EAT )
				
				if(has_export)
				{
					printf("%s\n<EXPORT TABLE>\n%s\n",LINE,LINE);
					printf("NAME\t\t: %s\tBASE\t: 0x%08X\tSTAMP\t: 0x%08X\n",file+img_eat->Name,img_eat->Base,img_eat->TimeDateStamp);
					printf("FUNCTIONS\t: %i\t\tNAMES\t: %i\t\tVERSION\t: %i.%i\n",img_eat->NumberOfFunctions,img_eat->NumberOfNames,img_eat->MajorVersion,img_eat->MinorVersion);				
					printf("EAT\t\t: 0x%08X\tEOT\t: 0x%08X\tENT\t: 0x%08X\n",img_eat->AddressOfFunctions,img_eat->AddressOfNameOrdinals,img_eat->AddressOfNames);
					printf("\nAddress:\tOrdinal:\tName:\n%s\n",LINE);				
				
					for(unsigned int i=0; i<img_eat->NumberOfFunctions; i++)
					{
						printf("0x%08X\t", *(DWORD*)(file+img_eat->AddressOfFunctions+i*4));
						printf("0x%08X\t", *(WORD*)(file+img_eat->AddressOfNameOrdinals+i*2));
						if( img_eat->NumberOfNames > i) printf("%s\n",file+*(DWORD*)(file+img_eat->AddressOfNames+i*4));
						else							printf("NO NAME\n");
					}																
				}
				printf("%s\n",LINE);	
				
				// PARSE IMPORT ADDRESS TABLE ( IAT )						
				printf("<IMPORT DIRECTORY>\n%s\nLIBRARY\t\tFUNCTION\n%s\n",LINE,LINE);
				
				for(IMAGE_IMPORT_DESCRIPTOR* i = img_iat; i->Characteristics != 0;  i++)
				{
					printf("%s\n",(char*)(file+i->Name));
					for(IMAGE_THUNK_DATA32* j=(IMAGE_THUNK_DATA32*)(file+i->OriginalFirstThunk); j->u1.Ordinal != 0; j++)										
						if((*(int*)j) & 0x80000000) printf("\t\t0x%08X (IMPORT BY ORDINAL)\n",j->u1.Ordinal-0x80000000);
						else printf("\t\t%s(...)\n",((IMAGE_IMPORT_BY_NAME*)(file+*(DWORD*)j))->Name);
				}
				
				printf("%s\n",LINE);								
				
				// SWITCH TO INTERACTIVE MODE IF REQUESTED	
				//if(argc == 3 && strcmp(argv[2],"-i")==0) Interactive(dos_header,pe_header,in);
													
			} else cout << "THIS IS NOT A VAILD PE BINARY ( failure while reading IMAGE_NT_SIGNATRE)" << endl << LINE << endl;	// Magic PE value not found
			
			
		} else cout << "THIS IS NOT A VAILD PE BINARY" << endl << LINE << endl;	// Magic MZ Value not found				
	}
	else cout << "Can not open binary" << endl;
	
	delete file;
	return EXIT_SUCCESS;
}

//-----------------------------------------------------------------------------
void Interactive(IMAGE_DOS_HEADER& dos_header, IMAGE_NT_HEADERS32& pe_header, ifstream* in)
{
	cout << "<INTERACTIVE MODE>" << endl << LINE << endl;
	char buf[256], u_cmd[256] = "";										
	while(strcmp(u_cmd,"quit"))
	{
		cout << "> "; gets(u_cmd);
						
		if(strcmp(u_cmd,"help")==0) Help();
		if(strncmp(u_cmd,"dumpsection",11)==0) 
		{
			strtok(u_cmd," ");	// REALLY BUGGY CODE BUT SINCE THE APPLICATION IS FOR MY PERSONAL USE ONLY ....
			dumpSection(strtok(NULL," "),strtok(NULL," "),atoi(strtok(NULL," ")));
		}
	}
}

//-----------------------------------------------------------------------------
void Help()
{
	cout << "COMMANDS:\n";
	cout << "\tdumpsection [SECTION] [FILENAME] [MODE]\n";
	cout << "\thelp\n";
	cout << "\tquit\n";
}

//-----------------------------------------------------------------------------
void dumpSection(const char* name, const char* file, unsigned int mode)
{
	cout << name << endl;
	cout << file << endl;
	cout << mode << endl;	
}

//-----------------------------------------------------------------------------
