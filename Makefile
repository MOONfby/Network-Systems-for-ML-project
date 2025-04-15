poxdir ?= /opt/pox/

# Complete the makefile as you prefer!
topo:
	@echo "starting the topology! (i.e., running mininet)"
	sudo python ./topology/topology.py

app:
	@echo "starting the baseController!"
	# Copy your controller to the POX folder
	cp applications/controller/* $(poxdir)ext/
	# Copy nfv click functions to the pox controller folder
	cp applications/nfv/*.click $(poxdir)ext/
	# Run controller that setups normal switches and CLICK nodes
	sudo python /opt/pox/pox.py baseController

test:
	@echo "starting test scenarios!"

clean:
	@echo "project files removed from pox directory!"
	# Remove files from ext dir in pox
	rm -f $(poxdir)ext/baseController.py $(poxdir)ext/click_wrapper.py $(poxdir)ext/*.click
	# Kill controller
	@# use the regexp trick to not match grep itself. And ignore the error if no pox running
	kill `ps -ef | grep pox[.py] | awk '{print $$2}'` || true
	# Clean mininet
	sudo mn -c
	# Kill click processes
	sudo killall click



