from opus import encoder
import pydub
import time

acceptable_channels = [1, 2]
acceptable_sr = [8000, 12000, 16000, 24000, 48000]


def convert_to_opus(f):
	aud = pydub.AudioSegment.from_mp3(f)

	print "sample rate:", aud.frame_rate, "| channels:", aud.channels, "| samples:", aud.frame_count()

	SAMPLE_RATE = min(acceptable_sr, key=lambda x: abs(x - aud.frame_rate))
	CHANNELS = min(acceptable_channels, key=lambda x: abs(x - aud.channels))

	if CHANNELS != aud.channels:
		print "different amount of channels setting to:", CHANNELS, "(", aud.channels, ")"
		aud = aud.set_channels(CHANNELS)

	if SAMPLE_RATE != aud.frame_rate:
		print "non-compatible sample rate resampling to:", SAMPLE_RATE, "(", aud.frame_rate, ")"
		aud = aud.set_frame_rate(SAMPLE_RATE)

	frames = []
	for x in range(1, 128):
		frame = ''
		for i in range(1, 960):
			frame = frame + aud.get_frame(i)
		frames.append(frame)

	enc = encoder.Encoder(SAMPLE_RATE, CHANNELS, "audio")
	enc._set_bitrate(4800)

	dat = ''
	for frame in frames:
		dat = dat + enc.encode(frame, 960)
		time.sleep(0)
	# print ''.join(x.encode('hex') for x in dat)
	return dat

convert_to_opus("./cork.mp3")