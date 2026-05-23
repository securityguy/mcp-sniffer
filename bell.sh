#!/bin/sh

#*******************************************************************************
# Copyright (c) 2026 Tenebris Technologies Inc.                                *
# Please see LICENSE file for details.                                         *
#*******************************************************************************

JWT="eyJhbGciOiJSUzI1NiIsImtpZCI6InhIa0dsdDFJNmZCaUpUaFVvQ1FWOENJcmFtZHFGSDg5NGJhVzQ2ejZFd0EiLCJ0eXAiOiJKV1QifQ.eyJleHAiOjE3NzkzMTU1MDQsIm5iZiI6MTc3OTMxMTkwNCwidmVyIjoiMS4wIiwiaXNzIjoiaHR0cHM6Ly9iZWxsc2Vuc2luZy5iMmNsb2dpbi5jb20vOTFmYThmMWMtNGRmOC00ZWIyLWEwY2UtZGI1MmRkZGE0MjQyL3YyLjAvIiwic3ViIjoiN2E4ZTIwYjktY2U2ZS00YzgxLWJlZDktMWY1ZjE3NmY5OTlkIiwiYXVkIjoiOWNhNGQxMDUtN2ZjMi00YjM5LWJkMjQtYWVmZGUyOTcxOGNlIiwiYWNyIjoiYjJjXzFhX3BvcnRhbF92Ml9zaWdudXBfc2lnbmluIiwibm9uY2UiOiIwMTllNDZiZC05NjRmLTcyZTMtOWQ2NS0wOTk0MzQzMjE0M2IiLCJpYXQiOjE3NzkzMTE5MDQsImF1dGhfdGltZSI6MTc3OTMwMzI5NSwidW5pcXVlX25hbWUiOiJlcmljQHRlbmVicmlzLmNvbSIsInRpZCI6IjkxZmE4ZjFjLTRkZjgtNGViMi1hMGNlLWRiNTJkZGRhNDI0MiJ9.aEihs5yWHsIKtt81ZVEYTZyw0ivK3mFJ7Dn-4j_Uky7XZXaTpInS1EEdX_b73cYSV6iQxjbgtA6AYcidDnMQDbNCbt5Vm4gelL3faqLn3YoWMT_aq9TZKulKrFN4QiP8iSycF7lYuJ6nZv_RuMxEindaKgw1TEfaVIND6_HTM4uvmKuj0OR2k_ln4e28puY0LLfFNz0gEN-I_RFSq3GFFW1FrtzzGDa3swuq-EQyeEuD0KNRBJQ0iqJU8lAx5NP6l6xMSJ1AH5WdjkT4w6QP7tiH6uAjxUTgrFGRypJJ90xkJ6npATpRQtpsJeFzewPo2p9qWxqT7W28teDYWqhscw"

curl -v -s -H "Authorization: Bearer $JWT" https://api-v2.bellsensing.com/sites/list
#curl -s -H "Authorization: Bearer $JWT" https://api-v2.bellsensing.com/sites/{siteId}

