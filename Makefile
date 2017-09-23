bootstrap:
	sudo apt-get install python-pip python3-dev build-essential libgmp3-dev
	sudo pip install --upgrade virtualenv
	virtualenv -p /usr/bin/python3 env
	. env/bin/activate
	pip install -r requirements.txt
	deactivate
