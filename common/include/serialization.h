#ifndef SERIALIZATION_H
#define SERIALIZATION_H

#include "protocol.h"

namespace Serialization
{

    template <typename T>
    /**
     * @brief The Serialize class
     * This class serialize every supperted
     * User defined type to a byte stream.
     * when calling serialize member you
     * get a pointer to the memory region
     * where the created stream is located.
     * The client is responsible for freeing
     * the allocated memory.
     *
     */
    class Serialize
    {
    public:
        /**
        * @brief serialize create a byte stream
        * from the parameter T
        * @param param The original Object for
        * which the byte stream is created
        * @return pointer (void *) to the
        * memory location of the stream
        */
       static void *serialize(const T &param);

       /**
        * @brief deserialize create an Object
        * of type T from the byte stream data
        * @param data the byte stream to
        * deserialize
        * @return an Object of type T
        */
       static T deserialize(void *data);
    };

    // Specialization
    template<>
    class Serialize<Message>
    {
    public:
        static void* serialize(const Message &message)
        {
            int data_size = strlen(message.data) ;
            int size = 2*STR_LEN + sizeof(Header) + data_size ;
            char *data;
            data = new char[size+1];
            memset(data, 0, size+1 );
            memcpy(data, (char*)&message, size - data_size);
            memcpy(data + size - data_size,(char*) message.data, data_size);
            return data;
        }

       static  Message deserialize(void *data)
        {
            Message message;
            int size = 2*STR_LEN + sizeof(Header);
            memcpy(&message,data, size );
            message.data = new char[message.header.length +1];
            memset(message.data, 0, message.header.length+1);
            memcpy(message.data, (char*)data + size, message.header.length);
            return message;
        }
    };


    template<>
    class Serialize<LogInOut>
    {
    public:
       static void* serialize(const LogInOut &log)
        {
            int size = STR_LEN + sizeof(Header);
            char *data;
            data = new char[size];
            memset(data, 0, STR_LEN);
            memcpy(data, &log, size);

            return data;
        }

        static LogInOut deserialize(void *data)
        {

            LogInOut log;
            char *ptr = (char*)data;
            int size = ptr[3] + sizeof(Header);
            memset(log.username, 0, STR_LEN);
            memcpy(&log.header,
                   data,
                   sizeof(Header) );

            memcpy(&log.username,
                   (char*)data +sizeof(Header),
                   size );
            ptr = nullptr;
            return log;
        }
    };

    template<>
    class Serialize<ControlInfo>
    {
    public:
       static void* serialize(const ControlInfo &controlInfo)
        {
           int size = sizeof(Header) +  sizeof(Entry) * controlInfo.header.length;
           char *data = new char[size];
           memcpy(data, (char*)&controlInfo.header, sizeof(Header));
           char *ptr = data + sizeof(Header);
           int offset = sizeof(Entry);
           if(controlInfo.entries)
           {
               for(int i = 0; i < controlInfo.header.length; i++)
               {
                   memcpy(ptr , (char*)&controlInfo.entries[i] , sizeof(Entry));
                   ptr += offset;
               }
           }

           return data;
        }

       static ControlInfo deserialize(void *data)
        {
           ControlInfo info;
           memcpy((char*)&info.header, data, sizeof(Header));
           char *ptr = (char*)data + sizeof(Header);
           if(info.header.length > 0)
           {
               int offset = sizeof(Entry);
               int size = sizeof(Header)
                       +  (sizeof(Entry)
                       *   info.header.length);
               info.entries = new Entry[size];
               for(int i = 0; i < info.header.length; i++)
               {
                   memcpy((char*)&info.entries[i], ptr, sizeof(Entry));
                   ptr += offset;
               }
           }
           return info;
        }
    };
}
#endif // SERIALIZATION_H

