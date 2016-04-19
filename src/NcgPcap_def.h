
/*!
 * \file NcgPcap_def.h
 *
 * \brief NcgPcap.dll����׃���ȶ��x�^�ļ���
 *
 * ԓ�^�ļ����x�����е�NcgPcap.dll��Č���׃��������Լ���Ķ��x��
 * ԓ�^�ļ���NcgPcap.h�^�ļ�������
 *
 */

#ifndef _NCGPCAP_DEF_H_
#define _NCGPCAP_DEF_H_

/*! ���ú����ӿڳɹ�ʱ����ֵ */
#define NPCAP_SUCC			0
/*! ���ú����ӿ�ʧ��ʱ����ֵ */
#define NPCAP_ERROR			-1

/*! ����ץ��ѡ����� npcap_findalldevs() �ӿڵĵ�һ������ */
#define LOCAL_CAPTURE		0
/*! Զ��ץ��ѡ����� npcap_findalldevs() �ӿڵĵ�һ������ */
#define REMOTE_CAPTURE		1

/*! errorBuf�Ĵ�С��256BYTES */
#define NPCAP_ERROR_BUFF_SIZE 256

/*! 
 * \brief �����豸�ӿڽṹ��
 *
 * �ýṹ���������ⲿ���������豸�ӿ���Ϣ���Թ�����ץ���Ľӿ�ѡ��
 */
typedef	struct npcap_if	npcap_if_t;

#endif