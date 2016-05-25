class BaseApiController < ApplicationController
	#methods that are run before a controller action
	before_action :parse_request, :authenticate_user_from_token!

	private 
		def authenticate_user_from_token!
			if !@json['api_token']
				render nothing: true, status: :unauthorized
			else
				@user = nil
				# compare 2 tokens
				# Devise.secure_compare helps avoid timing attacks. 
				# While the comparison algorithm used by Devise is not strictly speaking constant time 
				# as it uses newly allocated memory and is capable of invoking the Garbage Collector as a result, 
				# it is much nearer constant time then custom comparison routines. 
				# Similarly, the Users loop does not break, 
				# thus preventing an attacker from establishing api token validity based on response time.
				User.find_each do |u|			
					if Devise.secure_compare(u.api_token, @json['api_token'])
						@user = u 
					end
				end
			end
		end

		def parse_request
			#parsing JSON objects (string) to rails hash
			#to get raw data
			#request.body = io
			#when we execute io.read(), we read a line from the standard input.
			@json = JSON.parse(request.body.read)	
		end
end