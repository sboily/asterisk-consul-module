To run
------

    docker run p 5060:5060/udp -p 5038:5038 -p 8888:8888 -v $(pwd):/etc/asterisk -it quintana/asterisk bash
    asterisk -c
