
/*!
 * \file npcap_config.h
 *
 * \brief ȫ������ģ�K��ȫ��׃��ģ�K��
 *
 * ԓģ�K�б��������е�ȫ��׃����������������ɵ������ļ�npcap.conf.xml���xȡ�ġ�
 * ���а���������W�Pץ�����P��ý�w�W�Pץ�����P��ץ���ļ����g����·���ȡ�
 * ץ�����Pָ���ǣ���춱���ץ����ץ���W�����Q��ץ���ĸ����f�h�����Ķ˿ڵȣ�
 *				����h��ý�w�W�Pץ�����h�����Cip,�a����Ϣ���W�����Q�������f�h�����Ķ˿ڼ�ý�w���˿ڹ����ȡ�
 */

#ifndef _NPCAP_CONFIG_H_
#define _NPCAP_CONFIG_H_

#include <string>
#include <list>
#include <vector>

#include "npcap_internal_def.h"

using namespace std;

namespace CONFIG{

	bool					g_bOppositeCap = false;				///< �Ƿ�ָ���Զ�ץȡ
	char					g_szOppositeIp[16] = {0};			///< �Զ�ץȡIP
	list<npcap_if_internal> g_cascIfList;						///< �������������豸�ӿ��б�
	int						g_iSipPort = 0;						///< ��������SIP�˿�
	int						g_iClientPort = 0;					///< �������ؿͻ��˶˿�
	vector<int>				g_cascExtendPortList;				///< ��������ץ����չ�˿�
	list<npcap_media>		g_mediaList;						///< ý�������б�
	string					g_strWorkingDirectory;				///< ����Ŀ¼�����������Ŀ¼���������
}

#endif
