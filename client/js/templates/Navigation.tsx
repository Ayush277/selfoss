import React, { useContext } from 'react';
import classNames from 'classnames';
import EntriesPage from './EntriesPage';
import NavFilters from './NavFilters';
import NavSources from './NavSources';
import NavSearch from './NavSearch';
import NavTags from './NavTags';
import NavToolBar from './NavToolBar';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import * as icons from '../icons';
import { LoadingState } from '../requests/LoadingState';
import { useAllowedToWrite } from '../helpers/authorizations';
import { LocalizationContext } from '../helpers/i18n';

type NavigationProps = {
    entriesPage: EntriesPage | null;
    setNavExpanded: React.Dispatch<React.SetStateAction<boolean>>;
    navSourcesExpanded: boolean;
    setNavSourcesExpanded: React.Dispatch<React.SetStateAction<boolean>>;
    offlineState: boolean;
    allItemsCount: number;
    allItemsOfflineCount: number;
    unreadItemsCount: number;
    unreadItemsOfflineCount: number;
    starredItemsCount: number;
    starredItemsOfflineCount: number;
    sourcesState: LoadingState;
    setSourcesState: React.Dispatch<React.SetStateAction<LoadingState>>;
    sources: Array<object>;
    setSources: React.Dispatch<React.SetStateAction<Array<object>>>;
    tags: Array<object>;
    reloadAll: React.Dispatch<React.SetStateAction<Array<object>>>;
};

export default function Navigation(props: NavigationProps): JSX.Element {
    const {
        entriesPage,
        setNavExpanded,
        navSourcesExpanded,
        setNavSourcesExpanded,
        offlineState,
        allItemsCount,
        allItemsOfflineCount,
        unreadItemsCount,
        unreadItemsOfflineCount,
        starredItemsCount,
        starredItemsOfflineCount,
        sourcesState,
        setSourcesState,
        sources,
        setSources,
        tags,
        reloadAll,
    } = props;

    const _ = useContext(LocalizationContext);

    const canWrite = useAllowedToWrite();

    return (
        <React.Fragment>
            <div id="nav-logo"></div>
            {canWrite && (
                <button
                    accessKey="a"
                    id="nav-mark"
                    onClick={
                        entriesPage !== null
                            ? entriesPage.markVisibleRead
                            : null
                    }
                    disabled={entriesPage === null}
                >
                    {_('markread')}
                </button>
            )}

            <NavFilters
                setNavExpanded={setNavExpanded}
                offlineState={offlineState}
                allItemsCount={allItemsCount}
                allItemsOfflineCount={allItemsOfflineCount}
                unreadItemsCount={unreadItemsCount}
                unreadItemsOfflineCount={unreadItemsOfflineCount}
                starredItemsCount={starredItemsCount}
                starredItemsOfflineCount={starredItemsOfflineCount}
            />

            <div className="separator">
                <hr />
            </div>

            <div
                className={classNames({
                    'nav-ts-wrapper': true,
                    offline: offlineState,
                    online: !offlineState,
                })}
            >
                <NavTags tags={tags} setNavExpanded={setNavExpanded} />
                <NavSources
                    setNavExpanded={setNavExpanded}
                    navSourcesExpanded={navSourcesExpanded}
                    setNavSourcesExpanded={setNavSourcesExpanded}
                    sourcesState={sourcesState}
                    setSourcesState={setSourcesState}
                    sources={sources}
                    setSources={setSources}
                />
            </div>

            <div
                className={classNames({
                    'nav-unavailable': true,
                    offline: offlineState,
                    online: !offlineState,
                })}
            >
                <span className="fa-layers fa-2x">
                    <FontAwesomeIcon icon={icons.connection} />
                    <FontAwesomeIcon icon={icons.slash} />
                </span>
                <p>{_('offline_navigation_unavailable')}</p>
            </div>

            <div className="separator">
                <hr />
            </div>

            <NavSearch
                setNavExpanded={setNavExpanded}
                offlineState={offlineState}
            />

            <NavToolBar reloadAll={reloadAll} setNavExpanded={setNavExpanded} />
        </React.Fragment>
    );
}
