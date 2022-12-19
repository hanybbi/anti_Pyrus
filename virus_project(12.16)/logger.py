import logging

logger = logging.getLogger("no_virus")
logger.setLevel(logging.DEBUG)

formatter = logging.Formatter('[%(asctime)s] %(message)s')
# 탐지 시간, ip, 호스트명, 사용자명, pc명
# 파일명, 구분:바이러스, 바이러스명, 파일경로

streamingHandler = logging.StreamHandler()
streamingHandler.setFormatter(formatter)

logger.addHandler(streamingHandler)
logger.debug()