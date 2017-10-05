bootstrap: mongo
	sudo apt-get install -y python-pip python3-dev build-essential libgmp3-dev
	sudo pip install --upgrade virtualenv
	virtualenv -p /usr/bin/python3 env
	. env/bin/activate
	pip install -r requirements.txt
	deactivate

mongo:
	sudo apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv 0C49F3730359A14518585931BC711F9BA15703C6 # See: https://docs.mongodb.com/manual/tutorial/install-mongodb-on-ubuntu/
	echo "deb [ arch=amd64,arm64 ] http://repo.mongodb.org/apt/ubuntu xenial/mongodb-org/3.4 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-3.4.list
	sudo apt-get update
	sudo apt-get install -y mongodb-org
