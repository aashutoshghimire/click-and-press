#prepared by: Ashutosh Ghimire. Contact: aashutoshghimire7@gmail.com
#program to encrypt some text according to user defined key andd also decrypt it
require 'openssl'
require 'digest/sha1'
module Api
    module V1
        class EncryptsController < ApplicationController
            #this method is for encrytion of message with user defined key
            def create
                @key = encrypt_params['key'] 
                @text = encrypt_params['text'] 
                #avoid infinity loop by not accepting blank key
                if (!@key.length || @key.length == 0)
                    abort("ABORTED! Key cant be null")
                    exit(400)
                end
                #generate user defined key of constant 32 bytes
                key = seceretkey32(@key)
                crypt = ActiveSupport::MessageEncryptor.new(key)
                #encrypt the message with the key
                encrypted_data = crypt.encrypt_and_sign(@text)
                #prepare output data
                output = ['encrypted_data' => encrypted_data]


                render json: {statusCode: '200', message:'Encrypted Successfully', data:output} 

            end
            #this method is for decryption of encrypted text with same key
            def decrypt
                @key = encrypt_params['key'] 
                @text = encrypt_params['text'] 
                @key = @key.to_s
                if (!@key.length || @key.length == 0)
                    abort("ABORTED! Key cant be null")
                    exit(400)
                end
                key = seceretkey32(@key)
            
                crypt = ActiveSupport::MessageEncryptor.new(key)
                #decrpytion with the same key
                decrypted_data = crypt.decrypt_and_verify(@text)
                output = ['decrypted_data' => decrypted_data]


                render json: {statusCode: '200', message:'Encrypted Successfully', data:output} 

            end

            def encrypt_params
                params.permit(:key, :text)
            end

            
            def seceretkey32(key)
                #only take 32 bytes for larger input
                if key.length > 32
                   mood = key.scan(/.{32}/)
                   ourkey = mood.at(0)
                #make 32 bytes by repeating the smaller input
                else
                    mood = key
                    while mood.length <= 32
                        mood = mood + mood
                    end
                    if mood.length > 32
                        splited = mood.scan(/.{32}/)
                        ourkey = splited.at(0)
                    else
                        ourkey = mood
                    end

                end  
                ourkey #return statement
            end
              

          
        end
    end
end