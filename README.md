## Synopsis
This is my playground for implementing RTP/RTCP protocol and adjuscent pieces in Rust.  I have spent a fair amount of time with respective RFC documents, know my way around and attempted initial implementation in Go previously.  Rust version is learning from my previous mistakes and learning the language as well.  I do not know how far I will be able to progress.

Rust appears to be somewhat challenging mostly because it wants Sized types in some context and because I have to care about the lifetimes with buffers and related structures.  That drives API and general approach as to what should be allocated and what can be referenced.  The RTP/RTCP protocol itself is fairly complex.

The big advantage of the projects like this is it requires serious dive into the language, promotes and benefits from extensive unit testing, and is practical.  I have a few IP cameras from variety of vendors that are diverse in their server side implementation of the protocols (I know some interesting bits and behaviors that vary).  I can run an application against a particular camera and see how it responds.  And I can dump and analyze the responses/streams.

I am picking up some ideas from similar and not so similar projects on the github and improvise if I do not find something I need.  Perhaps others can benefit from reading my code.  Let's see where it goes.

In the Go version of the code I implmented RTP (not very safe, assumes server sends correct packets), RTCP, RTSP, rudimentary SDP, RTSP over HTTP (Apple extensions), some basics of h264 content parsing (NALU handling, Annex B).  I'll follow the same order here but try to be more thorough implementing validation wherever possible.  In the past I got stuck at handling multiple NALUs per packet and combining packets.  Just need more time to see how it appears from cameras to have a set of data for practice.

## TODO
- [ ] Implement RTP packet bulder (packetizer).
- [ ] Implement validations while building RTP packet to ensure permanent correctness.
- [ ] Implement BEDE extension parser and builder.
- [ ] Implement sequence number generator: unpredictable initial value, increment, multiplexing support.
- [ ] Implement RTCP parser.
- [ ] Implement RTCP builder.
- [ ] Implement simple SDP parser (this is one area I'd like to skimp on until later time).
- [ ] Implement digest algorithm for RTSP authentication.
- [ ] Implement message protocol for RTSP.
- [ ] Implement state machine for RTSP.
- [ ] Implement RTSP over HTTP.